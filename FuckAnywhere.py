# -*- coding: utf-8 -*-
# Author: key @ Yuanheng Lab

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IScannerInsertionPoint
from burp import IParameter

import re

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        print('FuckAnywhere - By key @ Yuanheng Lab')
        callbacks.setExtensionName("FuckAnywhere")
        callbacks.registerScannerCheck(self)

    def _build_payload(self):
        return "Your Payload"

    def _url_filter(self, url):
        try:
            url_index = url.index("?")
            url = url.substring(0, url_index)
        except:
            url = url
        result = re.findall("[\\w]+[\\.](3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|bz2|cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|mjs|mp2|mp3|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|woff2|xbm|xls|xlsx|xpm|xul|xwd|zip|zip)", url)
        if result != []:
            return False
        else:
            return True

    def _build_request_list(self, baseRequestResponse):
        request_list = []
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        # Check Parameters
        param_list = request_info.getParameters()
        url = request_info.getUrl().toString()
        if self._url_filter(url):
            if param_list != []:
                request_message = baseRequestResponse.getRequest()
                for p in param_list:
                    key = p.getName()
                    value = p.getValue()
                    ptype = p.getType()
                    payload = self._build_payload()
                    if (ptype == IParameter.PARAM_URL) or (ptype == IParameter.PARAM_BODY) or (ptype == IParameter.PARAM_COOKIE):
                        request_message = self._helpers.updateParameter(request_message, self._helpers.buildParameter(key, payload, ptype))
                        request_list.append(request_message)
                        request_message = self._helpers.updateParameter(request_message, self._helpers.buildParameter(key, value, ptype))
                    else:
                        value_start = p.getValueStart()
                        request_message_copy = request_message
                        request_message_str = self._helpers.bytesToString(request_message_copy)
                        request_message_list = list(request_message_str)
                        for i in range(len(value)):
                            request_message_list.pop(value_start)
                        for i in range(0,len(payload)):
                            request_message_list.insert(value_start+i, payload[i])
                        request_list.append(self._helpers.stringToBytes(''.join(request_message_list)))

            header_list = request_info.getHeaders()
            other_header_list = ["Accept-Charset", "Accept-Datetime", "Accept-Encoding", "Accept-Language", "Cache-Control", "Client-IP", "Connection", "Contact", "Cookie", "DNT", "Forwarded", "Forwarded-For", "Forwarded-For-Ip", "Forwarded-Proto", "From", "Host", "Max-Forwards", "Origin", "Pragma", "Referer", "TE", "True-Client-IP", "Upgrade", "User-Agent", "Via", "Warning", "X-Api-Version", "X-ATT-DeviceId", "X-Client-IP", "X-Correlation-ID", "X-Csrf-Token", "X-CSRFToken", "X-Custom-IP-Authorization", "X-Do-Not-Track", "X-Foo", "X-Foo-Bar", "X-Forward", "X-Forward-For", "X-Forward-Proto", "X-Forwarded", "X-Forwarded-By", "X-Forwarded-For", "X-Forwarded-For-Original", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto", "X-Forwarded-Protocol", "X-Forwarded-Scheme", "X-Forwarded-Server", "X-Forwarded-Ssl", "X-Forwarder-For", "X-Forwared-Host", "X-Frame-Options", "X-From", "X-Geoip-Country", "X-Host", "X-Http-Destinationurl", "X-Http-Host-Override", "X-Http-Method", "X-HTTP-Method-Override", "X-Http-Path-Override", "X-Https", "X-Htx-Agent", "X-Hub-Signature", "X-If-Unmodified-Since", "X-Imbo-Test-Config", "X-Insight", "X-Ip", "X-Ip-Trail", "X-Original-URL", "X-Originating-IP", "X-Override-URL", "X-ProxyUser-Ip", "X-Real-IP", "X-Remote-Addr", "X-Remote-IP", "X-Request-ID", "X-Requested-With", "X-Rewrite-URL", "X-UIDH", "X-Wap-Profile", "X-XSRF-TOKEN", "If-Modified-Since"]
            if header_list != []:
                for i in range(1, len(header_list)):
                    header_list = request_info.getHeaders()
                    # Header: Don't URLEncode
                    payload = self._helpers.urlDecode(self._build_payload())
                    tmp_header = header_list[i]
                    tmp_header_split = tmp_header.split(": ")
                    tmp_header_split[1] = payload
                    header_name = tmp_header_split[0]
                    if header_name in other_header_list:
                        other_header_list.remove(header_name)
                    header_list[i] = ": ".join(tmp_header_split)
                    request_message = self._helpers.buildHttpMessage(header_list, baseRequestResponse.getRequest()[request_info.getBodyOffset():])
                    request_list.append(request_message)

                for i in other_header_list:
                    header_list = request_info.getHeaders()
                    payload = self._helpers.urlDecode(self._build_payload())
                    header_list.add("{0}: {1}".format(i, payload))
                    request_message = self._helpers.buildHttpMessage(header_list, baseRequestResponse.getRequest()[request_info.getBodyOffset():])
                    request_list.append(request_message)
        return request_list


    def doPassiveScan(self, baseRequestResponse):
        request_list = self._build_request_list(baseRequestResponse)
        if request_list != []:
            for r in request_list:
                checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), r)

        return []
                    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
