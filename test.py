import  pyshark
import numpy


# def Compare_Wireshark_Data(trace_file1_location,trace_file2_location):
#     cap1 = pyshark.FileCapture(trace_file1_location, display_filter='sip')
#     cap2 = pyshark.FileCapture(trace_file2_location, display_filter='sip')
#     Request_Line1 = list()
#     Request_Line2 = list()
#     Result1 = list()
#     Result2 = list()
#     for pkt in cap1:
#         if pkt.highest_layer == 'SIP':
#             count = 0
#             if pkt['sip'].get_field_value('Method') == "INVITE":
#                 Request_Line1.append(pkt['sip'].get_field_value('Request-LINE'))
#                 # Request_Line.append(pkt['sip'].get_field_value('Method')+' ' + pkt['sip'].get_field_value('Via'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 # print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 # print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 # print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 #print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Max-Forwards'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Subject'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Content-Type'))
#                 if pkt['sip'].get_field_value('Content-Length') != None:
#                     Request_Line1.append('Content-Length : exist')
#             elif pkt['sip'].get_field_value('Method') == "ACK":
#                 Request_Line1.append(pkt['sip'].get_field_value('Request-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Method') == "BYE":
#                 Request_Line1.append(pkt['sip'].get_field_value('Request-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Status-Code') == "100":
#                 Request_Line1.append(pkt['sip'].get_field_value('Status-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Status-Code') == "180":
#                 Request_Line1.append(pkt['sip'].get_field_value('Status-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Status-Code') == "200":
#                 Request_Line1.append(pkt['sip'].get_field_value('Status-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line1.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))
#     for pkt in cap2:
#         if pkt.highest_layer == 'SIP':
#             count = 0
#             if pkt['sip'].get_field_value('Method') == "INVITE":
#                 Request_Line2.append(pkt['sip'].get_field_value('Request-LINE'))
#                 # Request_Line.append(pkt['sip'].get_field_value('Method')+' ' + pkt['sip'].get_field_value('Via'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Method') == "ACK":
#                 Request_Line2.append(pkt['sip'].get_field_value('Request-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Method') == "BYE":
#                 Request_Line2.append(pkt['sip'].get_field_value('Request-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Status-Code') == "100":
#                 Request_Line2.append(pkt['sip'].get_field_value('Status-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Status-Code') == "180":
#                 Request_Line2.append(pkt['sip'].get_field_value('Status-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))
#             elif pkt['sip'].get_field_value('Status-Code') == "200":
#                 Request_Line2.append(pkt['sip'].get_field_value('Status-LINE'))
#                 count = (pkt['sip'].get_field_value('Via').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
#                 count = (pkt['sip'].get_field_value('From').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
#                 count = (pkt['sip'].get_field_value('To').find(';'))
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
#                 count = (pkt['sip'].get_field_value('Call-ID').find('@'))
#                 # print(count)
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
#                 Request_Line2.append(
#                     pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))
#
#     print(Request_Line1)
#
#     print('file2 not contain file1')
#     for y in Request_Line2:
#         if y not in Request_Line1:
#             Result1.append(y)
#     print(Result1)
#     print('file1 not contain file2')
#     for z in Request_Line1:
#         if z not in Request_Line2:
#             Result2.append(z)
#     print(Result2)
#     cap1.close()
#     cap2.close()
#     return Result1 and Result2
#
#
# Compare_Wireshark_Data('42.pcap', '43.pcap')

Request_Line = list()
cap = pyshark.FileCapture('42.pcap', display_filter='sip')
for pkt in cap:
    if pkt.highest_layer == 'SIP':
        count = 0
        if pkt['sip'].get_field_value('Method') == "INVITE":
            print(pkt['sip'].get_field_value('msg_hdr'))
            Request_Line.append(pkt['sip'].get_field_value('Request-LINE'))
            # Request_Line.append(pkt['sip'].get_field_value('Method')+' ' + pkt['sip'].get_field_value('Via'))
            count = (pkt['sip'].get_field_value('Via').find(';'))
            # print(count)
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
            count = (pkt['sip'].get_field_value('From').find(';'))
            # print(count)
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
            count = (pkt['sip'].get_field_value('To').find(';'))
            # print(count)
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
            count = (pkt['sip'].get_field_value('Call-ID').find('@'))
            #print(count)
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
            #print(pkt['sip'].get_field_value('Max-Forwards'))
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Max-Forwards'))
            #print(pkt['sip'].get_field_value('Subject'))
            if pkt['sip'].get_field_value('Subject') != None:
                Request_Line.append(
                    pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Subject'))
            else:
                Request_Line.append(
                    'INVITE Subject is None ')
            Request_Line.append(
                pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Content-Type'))
            if pkt['sip'].get_field_value('Content-Length') != None:
                Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Content-Length is exist')
            else:
                print(Request_Line.append(pkt['sip'].get_field_value('Method') + ' :lack Content-Length '))
        # elif pkt['sip'].get_field_value('Method') == "ACK":
        #     Request_Line.append(pkt['sip'].get_field_value('Request-LINE'))
        #     count = (pkt['sip'].get_field_value('Via').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
        #     count = (pkt['sip'].get_field_value('From').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
        #     count = (pkt['sip'].get_field_value('To').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
        #     count = (pkt['sip'].get_field_value('Call-ID').find('@'))
        #     # print(count)
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Max-Forwards'))
        #     if pkt['sip'].get_field_value('Content-Length') != None:
        #         Request_Line.append(pkt['sip'].get_field_value('Method') + ' :Content-Length is exist')
        #     else:
        #         print(Request_Line.append(pkt['sip'].get_field_value('Method') + ' :lack Content-Length '))
        # elif pkt['sip'].get_field_value('Method') == "BYE":
        #     Request_Line.append(pkt['sip'].get_field_value('Request-LINE'))
        #     count = (pkt['sip'].get_field_value('Via').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
        #     count = (pkt['sip'].get_field_value('From').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('From')[0:count])
        #     count = (pkt['sip'].get_field_value('To').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('To')[0:count])
        #     count = (pkt['sip'].get_field_value('Call-ID').find('@'))
        #     # print(count)
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Method') + ' ' + pkt['sip'].get_field_value('CSeq'))
        # elif pkt['sip'].get_field_value('Status-Code') == "100":
        #     Request_Line.append(pkt['sip'].get_field_value('Status-LINE'))
        #     count = (pkt['sip'].get_field_value('Via').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
        #     count = (pkt['sip'].get_field_value('From').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
        #     count = (pkt['sip'].get_field_value('To').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
        #     count = (pkt['sip'].get_field_value('Call-ID').find('@'))
        #     # print(count)
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))
        # elif pkt['sip'].get_field_value('Status-Code') == "180":
        #     Request_Line.append(pkt['sip'].get_field_value('Status-LINE'))
        #     count = (pkt['sip'].get_field_value('Via').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
        #     count = (pkt['sip'].get_field_value('From').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
        #     count = (pkt['sip'].get_field_value('To').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
        #     count = (pkt['sip'].get_field_value('Call-ID').find('@'))
        #     # print(count)
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))
        # elif pkt['sip'].get_field_value('Status-Code') == "200":
        #     Request_Line.append(pkt['sip'].get_field_value('Status-LINE'))
        #     count = (pkt['sip'].get_field_value('Via').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Via')[0:count])
        #     count = (pkt['sip'].get_field_value('From').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('From')[0:count])
        #     count = (pkt['sip'].get_field_value('To').find(';'))
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('To')[0:count])
        #     count = (pkt['sip'].get_field_value('Call-ID').find('@'))
        #     # print(count)
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('Call-ID')[count:])
        #     Request_Line.append(
        #         pkt['sip'].get_field_value('Status-Code') + ' ' + pkt['sip'].get_field_value('CSeq'))


cap.close()
print(Request_Line)



