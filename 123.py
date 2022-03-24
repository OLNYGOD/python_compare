import  pyshark


cap = pyshark.FileCapture('42.pcap', display_filter='sip')

for pkt in cap:
    if pkt.highest_layer == 'SIP':
        Request_Line = list()
        count = 0
        if pkt['sip'].get_field_value('Method') == "INVITE":
            Request_Line.append(pkt['sip'].get_field_value('Request-LINE'))
            # Request_Line.append(pkt['sip'].get_field_value('Method')+' ' + pkt['sip'].get_field_value('Via'))
            count = (pkt['sip'].get_field_value('Via').find(';'))
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' Via ' + pkt['sip'].get_field_value('Via')[0:count])
            count = (pkt['sip'].get_field_value('From').find(';'))
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' From ' + pkt['sip'].get_field_value('From')[0:count])
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' To ' + pkt['sip'].get_field_value('To'))
            count = (pkt['sip'].get_field_value('Call-ID').find('@'))
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' Call-ID ' + pkt['sip'].get_field_value('Call-ID')[count:])
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' CSeq ' + pkt['sip'].get_field_value('CSeq'))
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' Max-Forwards ' + pkt['sip'].get_field_value('Max-Forwards'))
            if pkt['sip'].get_field_value('Subject') != None:
                Request_Line.append(
                    pkt['sip'].get_field_value('Method') + ' Subject ' + pkt['sip'].get_field_value('Subject'))
            else:
                Request_Line.append(
                    'INVITE Subject is None ')
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Content-Type'))
            if pkt['sip'].get_field_value('Content-Length') != None:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Content-Length is exist')
            else:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Content-Length lack')
            if pkt['sip'].get_field_value('Supported') != None:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' Supported ' + pkt['sip'].get_field_value('Supported'))
            else:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Supported lack')
            if pkt['sip'].get_field_value('Session-Expires') != None:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Session-Expires ' +pkt['sip'].get_field_value('Session-Expires'))
            else:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Session-Expires lack')
            if pkt['sip'].get_field_value('Min-SE') != None:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Min-SE ' +pkt['sip'].get_field_value('Min-SE'))
            else:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Content-Length lack ')
            print(Request_Line)
            #print(pkt['sip'].get_field_value('msg_hdr'))
cap.close()