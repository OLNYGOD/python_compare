import  pyshark
import pandas as pd

def Compare_Wireshark_Data(trace_file1_location,trace_file2_location):
    cap1 = pyshark.FileCapture(trace_file1_location, display_filter='sip')
    cap2 = pyshark.FileCapture(trace_file2_location, display_filter='sip')
    Request_Line1 = list()
    Request_Line2 = list()
    Result1 = list()
    Result2 = list()
    Result3 = {}


    for pkt in cap1:
        if pkt.highest_layer == 'SIP':
            count = 0
            if pkt['sip'].get_field_value('Method') == "INVITE" or pkt['sip'].get_field_value('Method') == "ACK" or pkt['sip'].get_field_value('Method') == "BYE":
                Request_Line1.append('Request-LINE :'+ pkt['sip'].get_field_value('Request-LINE'))
                # Request_Line.append(pkt['sip'].get_field_value('Method')+' ' + pkt['sip'].get_field_value('Via'))
                count = (pkt['sip'].get_field_value('Via').find(';'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Method') + ' Via ' + pkt['sip'].get_field_value('Via')[0:count])
                count = (pkt['sip'].get_field_value('From').find(';'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Method') + ' From ' + pkt['sip'].get_field_value('From')[0:count])
                count = (pkt['sip'].get_field_value('To').find(';'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Method') + ' To ' + pkt['sip'].get_field_value('To')[0:count])
                count = (pkt['sip'].get_field_value('Call-ID').find('@'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Method') + ' Call-ID ' + pkt['sip'].get_field_value('Call-ID')[count:])
                Request_Line1.append(
                    pkt['sip'].get_field_value('Method') + ' CSeq ' + pkt['sip'].get_field_value('CSeq'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Method') + ' Max-Forwards ' + pkt['sip'].get_field_value(
                        'Max-Forwards'))
                if pkt['sip'].get_field_value('Contact') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Method') + ' Contact ' + pkt['sip'].get_field_value(
                            'Contact'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Method') +
                                         'Contact is None ')
                if pkt['sip'].get_field_value('Record - Route') != None:
                    count = (pkt['sip'].get_field_value('Record - Route').find('@'))
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Method') + ' Record - Route ' + pkt['sip'].get_field_value(
                            'Record - Route')[count:])
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Method')+
                        ' Record - Route is None ')
                if pkt['sip'].get_field_value('Subject') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Method') + ' Subject ' + pkt['sip'].get_field_value('Subject'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Method')+
                        ' Subject is None ')
                if pkt['sip'].get_field_value('Content-Type') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Method') + ' Content-Type ' + pkt['sip'].get_field_value('Content-Type'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Method') + ' :Content-Type is None')
                if pkt['sip'].get_field_value('Content-Length') != None:
                    Request_Line1.append(pkt['sip'].get_field_value('Method') + ' :Content-Length is exist')
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Method') + ' :Content-Length is None')
                if pkt['sip'].get_field_value('Supported') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Method') + ' Supported ' + pkt['sip'].get_field_value('Supported'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Method') + ' :Supported is None')
                if pkt['sip'].get_field_value('Session-Expires') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Method') + ' Session-Expires ' + pkt['sip'].get_field_value(
                            'Session-Expires'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Method') + ' :Session-Expires is None')
                if pkt['sip'].get_field_value('Min-SE') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Method') + ' : Min-SE ' + pkt['sip'].get_field_value('Min-SE'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Method') + ' :Min-SE is None ')
            elif pkt['sip'].get_field_value('Status-Code') == "100" or pkt['sip'].get_field_value('Status-Code') == "180" or pkt['sip'].get_field_value('Status-Code') == "200":
                Request_Line1.append('Status-LINE :'+pkt['sip'].get_field_value('Status-Line'))
                # Request_Line.append(pkt['sip'].get_field_value('Method')+' ' + pkt['sip'].get_field_value('Via'))
                count = (pkt['sip'].get_field_value('Via').find(';'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Status-Code') + ' Via ' + pkt['sip'].get_field_value('Via')[0:count])
                count = (pkt['sip'].get_field_value('From').find(';'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Status-Code') + ' From ' + pkt['sip'].get_field_value('From')[0:count])
                count = (pkt['sip'].get_field_value('To').find(';'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Status-Code') + ' To ' + pkt['sip'].get_field_value('To')[0:count])
                count = (pkt['sip'].get_field_value('Call-ID').find('@'))
                Request_Line1.append(
                    pkt['sip'].get_field_value('Status-Code') + ' Call-ID ' + pkt['sip'].get_field_value('Call-ID')[count:])
                Request_Line1.append(
                    pkt['sip'].get_field_value('Status-Code') + ' CSeq ' + pkt['sip'].get_field_value('CSeq'))
                if pkt['sip'].get_field_value('Contact') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Contact ' + pkt['sip'].get_field_value(
                            'Contact'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') +
                                         'Contact is None ')
                if pkt['sip'].get_field_value('Max-Forwards') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Max-Forwards ' + pkt['sip'].get_field_value(
                            'Max-Forwards'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') +
                                         'Max-Forwards is None ')
                if pkt['sip'].get_field_value('Record - Route') != None:
                    count = (pkt['sip'].get_field_value('Record - Route').find('@'))
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Record - Route ' + pkt['sip'].get_field_value(
                            'Record - Route')[count:])
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') +
                                         ' Record - Route is None ')
                if pkt['sip'].get_field_value('Subject') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Subject ' + pkt['sip'].get_field_value('Subject'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') +
                                         ' Subject is None ')
                if pkt['sip'].get_field_value('Content-Type') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Content-Type ' + pkt['sip'].get_field_value(
                            'Content-Type'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') + ' :Content-Type is None')
                if pkt['sip'].get_field_value('Content-Length') != None:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') + ' :Content-Length is exist')
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') + ' :Content-Length is None')
                if pkt['sip'].get_field_value('Supported') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Supported ' + pkt['sip'].get_field_value('Supported'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') + ' :Supported is None')
                if pkt['sip'].get_field_value('Session-Expires') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Session-Expires ' + pkt['sip'].get_field_value(
                            'Session-Expires'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') + ' :Session-Expires is None')
                if pkt['sip'].get_field_value('Min-SE') != None:
                    Request_Line1.append(
                        pkt['sip'].get_field_value('Status-Code') + ' : Min-SE ' + pkt['sip'].get_field_value('Min-SE'))
                else:
                    Request_Line1.append(pkt['sip'].get_field_value('Status-Code') + ' :Min-SE is None ')
    for pkt in cap2:
        if pkt.highest_layer == 'SIP':
            count = 0
            if pkt['sip'].get_field_value('Method') == "INVITE" or pkt['sip'].get_field_value('Method') == "ACK" or pkt[
                'sip'].get_field_value('Method') == "BYE":
                Request_Line2.append('Request-LINE :'+ pkt['sip'].get_field_value('Request-LINE'))
                # Request_Line.append(pkt['sip'].get_field_value('Method')+' ' + pkt['sip'].get_field_value('Via'))
                count = (pkt['sip'].get_field_value('Via').find(';'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Method') + ' Via ' + pkt['sip'].get_field_value('Via')[0:count])
                count = (pkt['sip'].get_field_value('From').find(';'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Method') + ' From ' + pkt['sip'].get_field_value('From')[0:count])
                count = (pkt['sip'].get_field_value('To').find(';'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Method') + ' To ' + pkt['sip'].get_field_value('To')[0:count])
                count = (pkt['sip'].get_field_value('Call-ID').find('@'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Method') + ' Call-ID ' + pkt['sip'].get_field_value('Call-ID')[count:])
                Request_Line2.append(
                    pkt['sip'].get_field_value('Method') + ' CSeq ' + pkt['sip'].get_field_value('CSeq'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Method') + ' Max-Forwards ' + pkt['sip'].get_field_value(
                        'Max-Forwards'))
                if pkt['sip'].get_field_value('Contact') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Method') + ' Contact ' + pkt['sip'].get_field_value(
                            'Contact'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') +
                                         'Contact is None ')
                if pkt['sip'].get_field_value('Record - Route') != None:
                    count = (pkt['sip'].get_field_value('Record - Route').find('@'))
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Method') + ' Record - Route ' + pkt['sip'].get_field_value(
                            'Record - Route')[count:])
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') +
                                         ' Record - Route is None ')
                if pkt['sip'].get_field_value('Subject') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Method') + ' Subject ' + pkt['sip'].get_field_value('Subject'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') +
                                         ' Subject is None ')
                if pkt['sip'].get_field_value('Content-Type') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Method') + ' Content-Type ' + pkt['sip'].get_field_value(
                            'Content-Type'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') + ' :Content-Type is None')
                if pkt['sip'].get_field_value('Content-Length') != None:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') + ' :Content-Length is exist')
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') + ' :Content-Length is None')
                if pkt['sip'].get_field_value('Supported') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Method') + ' Supported ' + pkt['sip'].get_field_value('Supported'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') + ' :Supported is None')
                if pkt['sip'].get_field_value('Session-Expires') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Method') + ' Session-Expires ' + pkt['sip'].get_field_value(
                            'Session-Expires'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') + ' :Session-Expires is None')
                if pkt['sip'].get_field_value('Min-SE') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Method') + ' : Min-SE ' + pkt['sip'].get_field_value('Min-SE'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Method') + ' :Min-SE is None ')

            elif pkt['sip'].get_field_value('Status-Code') == "100" or pkt['sip'].get_field_value(
                    'Status-Code') == "180" or pkt['sip'].get_field_value('Status-Code') == "200":
                Request_Line2.append('Status-LINE :'+ pkt['sip'].get_field_value('Status-Line'))
                # Request_Line.append(pkt['sip'].get_field_value('Method')+' ' + pkt['sip'].get_field_value('Via'))
                count = (pkt['sip'].get_field_value('Via').find(';'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Status-Code') + ' Via ' + pkt['sip'].get_field_value('Via')[0:count])
                count = (pkt['sip'].get_field_value('From').find(';'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Status-Code') + ' From ' + pkt['sip'].get_field_value('From')[0:count])
                count = (pkt['sip'].get_field_value('To').find(';'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Status-Code') + ' To ' + pkt['sip'].get_field_value('To')[0:count])
                count = (pkt['sip'].get_field_value('Call-ID').find('@'))
                Request_Line2.append(
                    pkt['sip'].get_field_value('Status-Code') + ' Call-ID ' + pkt['sip'].get_field_value('Call-ID')[
                                                                              count:])
                Request_Line2.append(
                    pkt['sip'].get_field_value('Status-Code') + ' CSeq ' + pkt['sip'].get_field_value('CSeq'))
                if pkt['sip'].get_field_value('Contact') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Contact ' + pkt['sip'].get_field_value(
                            'Contact'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') +
                                         'Contact is None ')
                if pkt['sip'].get_field_value('Max-Forwards') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Max-Forwards ' + pkt['sip'].get_field_value(
                            'Max-Forwards'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') +
                                         'Max-Forwards is None ')
                if pkt['sip'].get_field_value('Record - Route') != None:
                    count = (pkt['sip'].get_field_value('Record - Route').find('@'))
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Record - Route ' + pkt['sip'].get_field_value(
                            ' Record - Route')[count:])
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') +
                                         ' Record - Route is None ')
                if pkt['sip'].get_field_value('Subject') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Subject ' + pkt['sip'].get_field_value('Subject'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') +
                                         ' Subject is None ')
                if pkt['sip'].get_field_value('Content-Type') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Content-Type ' + pkt['sip'].get_field_value(
                            'Content-Type'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') + ' :Content-Type is None')
                if pkt['sip'].get_field_value('Content-Length') != None:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') + ' :Content-Length is exist')
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') + ' :Content-Length is None')
                if pkt['sip'].get_field_value('Supported') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Supported ' + pkt['sip'].get_field_value(
                            'Supported'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') + ' :Supported is None')
                if pkt['sip'].get_field_value('Session-Expires') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Status-Code') + ' Session-Expires ' + pkt['sip'].get_field_value(
                            'Session-Expires'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') + ' :Session-Expires is None')
                if pkt['sip'].get_field_value('Min-SE') != None:
                    Request_Line2.append(
                        pkt['sip'].get_field_value('Status-Code') + ' : Min-SE ' + pkt['sip'].get_field_value('Min-SE'))
                else:
                    Request_Line2.append(pkt['sip'].get_field_value('Status-Code') + ' :Min-SE is None ')


    #print(Request_Line1)
    #print(Request_Line2)

    #print('file2 not contain file1')
    for y in Request_Line2:
        if y not in Request_Line1:
            Result1.append(y)
    #print(Result1)
    #print('file1 not contain file2')
    for z in Request_Line1:
        if z not in Request_Line2:
            Result2.append(z)
    #print(Result2)
    Result3 = [Result1, Result2]
    #print(Result3)
    df = pd.DataFrame(Result3, )
    print(df)
    cap1.close()
    cap2.close()
    return Result1 and Result2


Compare_Wireshark_Data('42.pcap', '43.pcap')



