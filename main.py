import tkinter.filedialog as filedialog
import tkinter as tk
import  pyshark

file1 = ''
file2 = ''
mybutton_3 = ''

root = tk.Tk()
root.title('my window')
root.geometry('600x200')
lbl_1 = tk.Label(root, text='輸入檔案路徑', fg='#263238', font=('Arial', 12))
lbl_1.grid(column=0, row=0)
entry_1 = tk.Entry(root)
entry_1.grid(column=10, row=0)

lbl_2 = tk.Label(root, text='輸入檔案路徑', fg='#263238', font=('Arial', 12))
lbl_2.grid(column=0, row=10)
entry_2 = tk.Entry(root)
entry_2.grid(column=10, row=10)

entry_3 = tk.Entry(root)
entry_3.grid(column=0, row=30)
entry_3.get()



def button_event_1():
    global file1
    print("return button" + file1)
    entry_1.delete(0, 'end')
    file1 = filedialog.askopenfilename(parent=root, initialdir='~/', title='選取檔案',
                                           filetypes=[("pcap files", "*.pcap")])
    #print(type(file_path))
    #print(file_path)
    if not file1:
        print('file path is empty')
        file1 = ''
    else:
        with open(file1, 'r') as f:
            # f.seek(32, 0)
            # #print(f.read())
            # entry_1['text'] = f
            entry_1.insert(0, file1)
    #print(file1)
    #return "123321"


def button_event_2():
    global file2
    entry_2.delete(0, 'end')
    #print("return button2" + file2)
    file2 = filedialog.askopenfilename(parent=root, initialdir='~/', title='選取檔案',
                                           filetypes=[("pcap files", "*.pcap")])
    #print(type(file_path))
    #print(file_path)
    if not file2:
        file2 = ''
        print('file path is empty')
    else:
        with open(file2, 'r') as f:
            # f.seek(32, 0)
            # #print(f.read())
            # entry_1['text'] = f
            entry_2.insert(0, file2)
    #print(file2)
    #return file2


def Compare_Wireshark_Data(trace_file1_location,trace_file2_location):
    #print(456)
    #if trace_file1_location == '':
        #print(789)
    #print(file2)
    if entry_1.get() !='' and entry_2.get() != '':
        cap1 = pyshark.FileCapture(trace_file1_location, display_filter='sip')
        cap2 = pyshark.FileCapture(trace_file2_location, display_filter='sip')
        Request_Line1 = list()
        Request_Line2 = list()
        Result = list()
        for pkt in cap1:
            if pkt.highest_layer == 'SIP':
                if pkt['sip'].get_field_value('Method') == "INVITE" or pkt['sip'].get_field_value('Method') == "ACK" or pkt['sip'].get_field_value('Method') == "BYE":
                    Request_Line1.append(pkt['sip'].get_field_value('Request-LINE'))
        for pkt in cap2:
            if pkt.highest_layer == 'SIP':
                if pkt['sip'].get_field_value('Method') == "INVITE" or pkt['sip'].get_field_value('Method') == "ACK" or pkt['sip'].get_field_value('Method') == "BYE":
                    Request_Line2.append(pkt['sip'].get_field_value('Request-LINE'))

        for y in Request_Line2:
            if y not in Request_Line1:
                Result.append(y)
        print(Result)
        cap1.close()
        cap2.close()
        # trace_file1_location.close()
        # trace_file2_location.close()
        return Result
    else:
        print('please enter file')

mybutton_1 = tk.Button(root, text='button', command=button_event_1)

mybutton_1.grid(column=20, row=0 )
#print("return" + file1)
mybutton_2 = tk.Button(root, text='button', command=button_event_2)
mybutton_2.grid(column=20, row=10 )
#print("return2" +file2)
mybutton_3 = tk.Button(root, text='button', command=lambda:Compare_Wireshark_Data(file1, file2))
#print(123)
mybutton_3.grid(column=20, row=20 )

root.mainloop()

