package tshark

func extractPayload(node map[string]any, layers map[string]any) string {
	if s := pickFirstString(
		findStringByPath(node, "layers.http.http_file_data"),
		findStringByPath(node, "layers.data.data_data"),
		findStringByPath(node, "layers.websocket.websocket.payload"),
		findStringByPath(node, "layers.websocket.websocket_payload"),
		findStringByPath(node, "layers.tcp.tcp_payload"),
		findStringByPath(node, "layers.usb.usb_frame_data"),
		findStringByPath(node, "layers.usb.usb_control_response"),
		findStringByPath(node, "layers.usb.usb_capdata"),
		findStringByPath(node, "layers.usb.usb_data_fragment"),
		findBySuffix(layers, "httprequestline"),
		findBySuffix(layers, "httpresponseline"),
		findBySuffix(layers, "httpfiledata"),
		findBySuffix(layers, "datadata"),
		findBySuffix(layers, "websocketpayload"),
		findBySuffix(layers, "tcppayload"),
		findBySuffix(layers, "usbframedata"),
		findBySuffix(layers, "usbcontrolresponse"),
		findBySuffix(layers, "usbcapdata"),
		findBySuffix(layers, "usbdatafragment"),
	); s != "" {
		return s
	}

	if s := pickFirstString(
		findStringByPath(node, "layers._ws.col.info"),
		findBySuffix(layers, "colinfo"),
	); s != "" {
		return s
	}

	return ""
}

func buildPacketInfo(node map[string]any, layers map[string]any) string {
	if s := buildHTTPInfo(node, layers); s != "" {
		return s
	}

	if s := pickFirstString(
		findStringByPath(node, "layers._ws.col.info"),
		findStringByPath(node, "layers._ws.col.Info"),
		findBySuffix(layers, "colinfo"),
	); s != "" {
		return s
	}

	if s := buildDNSInfo(node, layers); s != "" {
		return s
	}

	if s := pickFirstString(
		findBySuffix(layers, "expertmessage"),
		findBySuffix(layers, "requestline"),
		findBySuffix(layers, "responseline"),
		findBySuffix(layers, "qryname"),
		findBySuffix(layers, "msg"),
		findBySuffix(layers, "text"),
	); s != "" {
		return s
	}

	return ""
}

func buildHTTPInfo(node map[string]any, layers map[string]any) string {
	method := pickFirstString(
		findStringByPath(node, "layers.http.http_request_method"),
		findBySuffix(layers, "httprequestmethod"),
	)
	uri := pickFirstString(
		findStringByPath(node, "layers.http.http_request_uri"),
		findStringByPath(node, "layers.http.http_request_full_uri"),
		findBySuffix(layers, "httprequesturi"),
	)
	if method != "" {
		if uri != "" {
			return method + " " + uri
		}
		return method
	}

	code := pickFirstString(
		findStringByPath(node, "layers.http.http_response_code"),
		findBySuffix(layers, "httpresponsecode"),
	)
	phrase := pickFirstString(
		findStringByPath(node, "layers.http.http_response_phrase"),
		findBySuffix(layers, "httpresponsephrase"),
	)
	if code != "" {
		if phrase != "" {
			return code + " " + phrase
		}
		return code
	}

	if s := pickFirstString(
		findStringByPath(node, "layers.http.http_request_line"),
		findStringByPath(node, "layers.http.http_response_line"),
		findBySuffix(layers, "httprequestline"),
		findBySuffix(layers, "httpresponseline"),
	); s != "" {
		return s
	}

	return ""
}

func buildDNSInfo(node map[string]any, layers map[string]any) string {
	name := pickFirstString(
		findStringByPath(node, "layers.dns.dns_qry_name"),
		findBySuffix(layers, "dnsqryname"),
	)
	typeText := pickFirstString(
		findBySuffix(layers, "dnsqrytypename"),
		findBySuffix(layers, "dnstype"),
	)
	if name == "" {
		return ""
	}
	if typeText != "" {
		return typeText + " " + name
	}
	return name
}
