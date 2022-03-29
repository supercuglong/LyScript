# -*- coding: utf-8 -*-
import socket
import struct
import time
from ctypes import *
class MyStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("Command_String_A", c_char * 256),
        ("Command_String_B", c_char * 256),
        ("Command_String_C", c_char * 256),
        ("Command_String_D", c_char * 256),
        ("Command_String_E", c_char * 256),
        ("Command_int_A",c_longlong),
        ("Command_int_B", c_longlong),
        ("Command_int_C", c_longlong),
        ("Command_int_D", c_longlong),
        ("Command_int_E", c_longlong),
        ("Count", c_int),
        ("Flag", c_int),
    ]
    def pack(self):
        buffer = struct.pack("< 256s 256s 256s 256s 256s q q q q q i i",self.Command_String_A,self.Command_String_B,self.Command_String_C,self.Command_String_D,self.Command_String_E,
                             self.Command_int_A,self.Command_int_B,self.Command_int_C,self.Command_int_D,self.Command_int_E,
                             self.Count,self.Flag)
        return buffer
    def unpack(self,buffer):
        (self.Command_String_A,self.Command_String_B,self.Command_String_C,self.Command_String_D,self.Command_String_E,
         self.Command_int_A,self.Command_int_B,self.Command_int_C,self.Command_int_D,self.Command_int_E,
         self.Count,self.Flag) = struct.unpack("< 256s 256s 256s 256s 256s q q q q q i i",buffer)
class MyDebug(object):
    def __init__(self,address="127.0.0.1",port=6666):
        self.address = address
        self.port = port
        self.sock = None
    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(3)
            self.sock.connect((self.address,self.port))
            return 1
        except Exception:
            return 0
    def is_connect(self):
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "IsConnect".encode("utf8")
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)

            recv_flag = self.sock.recv(7)
            if recv_flag.decode("utf8") == "success":
                return True
            else:
                return False
        except Exception:
            return False
    def close(self):
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "Exit".encode("utf8")
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            return True
        except Exception:
            return False
    def send_recv_struct(self,send_struct):
        try:
            recv_struct = MyStruct()
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_data = self.sock.recv(8192)
            if recv_data == 0 or len(recv_data) == 0 or recv_data == None:
                return None
            recv_struct.unpack(recv_data)
            return recv_struct
        except Exception:
            return None
    def get_register(self,register):
        ptr = MyStruct()
        ptr.Command_String_A = "GetRegister".encode("utf8")
        ptr.Command_String_B = register.upper().encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        return recv_struct.Command_int_A
    def set_register(self,register,value):
        ptr = MyStruct()
        ptr.Command_String_A = "SetRegister".encode("utf8")
        ptr.Command_String_B = register.upper().encode("utf8")
        ptr.Command_int_A = value
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def set_debug(self,action):
        ptr = MyStruct()
        ptr.Command_String_A = "SetDebug".encode("utf8")
        ptr.Command_String_B = action.upper().encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def set_debug_count(self,action,count):
        ptr = MyStruct()
        ptr.Command_String_A = "SetDebug".encode("utf8")
        ptr.Command_String_B = action.encode("utf8")
        for index in range(1,count):
            recv_struct = self.send_recv_struct(ptr)
            time.sleep(0.1)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def get_flag_register(self,register):
        ptr = MyStruct()
        ptr.Command_String_A = "GetFlagRegister".encode("utf8")
        ptr.Command_String_B = register.upper().encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def set_flag_register(self,register,value):
        ptr = MyStruct()
        ptr.Command_String_A = "SetFlagRegister".encode("utf8")
        ptr.Command_String_B = register.upper().encode("utf8")
        if value == True:
            ptr.Command_int_A = True
        else:
            ptr.Command_int_A = False
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def set_breakpoint(self,address,delete = False):
        ptr = MyStruct()
        if delete == False:
            ptr.Command_String_A = "SetBreakPoint".encode("utf8")
            ptr.Command_String_B = "SET".encode("utf8")
            ptr.Command_int_A = address
        if delete == True:
            ptr.Command_String_A = "SetBreakPoint".encode("utf8")
            ptr.Command_String_B = "DELETE".encode("utf8")
            ptr.Command_int_A = address
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def set_hardware_breakpoint(self,address,type = 0):
        ptr = MyStruct()
        ptr.Command_String_A = "SetHardwareBreakPoint".encode("utf8")
        ptr.Command_int_A = address
        ptr.Command_int_b = type
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def delete_hardware_breakpoint(self,address):
        ptr = MyStruct()
        ptr.Command_String_A = "DeleteHardwareBreakPoint".encode("utf8")
        ptr.Command_int_A = address
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def get_disasm_code(self,address,count):
        ret_list = []
        send_struct = MyStruct()
        send_struct.Command_String_A = "DisasmCode".encode("utf8")
        send_struct.Command_int_A = address
        send_struct.Command_int_B = count
        try:
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_buffer = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
            if recv_buffer != 0:
                for index in range(0,recv_buffer):
                    dic = {"addr": 0, "opcode": None}

                    recv_disasm = self.sock.recv(264)

                    (addr,opcode) = struct.unpack("< q 256s",recv_disasm)
                    asm = opcode.decode("utf8").replace('\0','')

                    dic.update({"addr": addr, "opcode": asm})
                    ret_list.append(dic)
                return ret_list
            else:
                return False
        except Exception:
            return False
    def scan_memory_one(self,pattern):
        ptr = MyStruct()
        ptr.Command_String_A = "ScanMemory".encode("utf8")
        ptr.Command_String_B = pattern.encode("utf8")

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            recv_address = recv_struct.Command_int_A
            return recv_address
        else:
            return False
        return False
    def scan_memory_all(self,pattern):
        send_struct = MyStruct()
        send_struct.Command_String_A = "ScanMemoryAll".encode("utf8")
        send_struct.Command_String_B = pattern.encode("utf8")
        return_list = []
        try:
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_buffer = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
            if recv_buffer != 0:
                for index in range(0,recv_buffer):
                    recv_address = int.from_bytes(self.sock.recv(8), byteorder="little", signed=False)
                    return_list.append(recv_address)
                return return_list
            else:
                return False
        except Exception:
            return False
    def read_memory_byte(self,address):
        ptr = MyStruct()
        ptr.Command_String_A = "ReadMemoryByte".encode("utf8")
        ptr.Command_int_A = address
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            recv_address = recv_struct.Command_int_A
            return recv_address
        else:
            return False
        return False
    def read_memory_word(self,address):
        ptr = MyStruct()
        ptr.Command_String_A = "ReadMemoryWord".encode("utf8")
        ptr.Command_int_A = address

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            recv_address = recv_struct.Command_int_A
            return recv_address
        else:
            return False
        return False
    def read_memory_dword(self,address):
        ptr = MyStruct()
        ptr.Command_String_A = "ReadMemoryDword".encode("utf8")
        ptr.Command_int_A = address

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            recv_address = recv_struct.Command_int_A
            return recv_address
        else:
            return False
        return False
    def read_memory_qword(self,address):
        ptr = MyStruct()
        ptr.Command_String_A = "ReadMemoryQword".encode("utf8")
        ptr.Command_int_A = address

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            recv_address = recv_struct.Command_int_A
            return recv_address
        else:
            return False
        return False
    def read_memory_ptr(self,address):
        ptr = MyStruct()
        ptr.Command_String_A = "ReadMemoryPtr".encode("utf8")
        ptr.Command_int_A = address
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            recv_address = recv_struct.Command_int_A
            return recv_address
        else:
            return False
        return False
    def write_memory_byte(self,address,value):
        ptr = MyStruct()
        ptr.Command_String_A = "WriteMemoryByte".encode("utf8")
        ptr.Command_int_A = address
        ptr.Command_int_B = value

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def write_memory_word(self,address,value):
        ptr = MyStruct()
        ptr.Command_String_A = "WriteMemoryWord".encode("utf8")
        ptr.Command_int_A = address
        ptr.Command_int_B = value
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def write_memory_dword(self,address,value):
        ptr = MyStruct()
        ptr.Command_String_A = "WriteMemoryDword".encode("utf8")
        ptr.Command_int_A = address
        ptr.Command_int_B = value

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def write_memory_qword(self,address,value):
        ptr = MyStruct()
        ptr.Command_String_A = "WriteMemoryQword".encode("utf8")
        ptr.Command_int_A = address
        ptr.Command_int_B = value

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def write_memory_ptr(self,address,value):
        ptr = MyStruct()
        ptr.Command_String_A = "WriteMemoryPtr".encode("utf8")
        ptr.Command_int_A = address
        ptr.Command_int_B = value

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def create_alloc(self,size):
        ptr = MyStruct()
        ptr.Command_String_A = "CreateAlloc".encode("utf8")
        ptr.Command_int_A = size

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            recv_address = recv_struct.Command_int_A
            return recv_address
        else:
            return False
        return False
    def delete_alloc(self,address):
        ptr = MyStruct()
        ptr.Command_String_A = "DeleteAlloc".encode("utf8")
        ptr.Command_int_A = address

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def get_local_base(self):
        ptr = MyStruct()
        ptr.Command_String_A = "GetLocalBase".encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            base_addr = recv_struct.Command_int_A
            return base_addr
        else:
            return False
        return False
    def get_local_protect(self):
        ptr = MyStruct()
        ptr.Command_String_A = "GetLocalProtect".encode("utf8")

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            base_addr = recv_struct.Command_int_A
            return base_addr
        else:
            return False
        return False
    def get_local_size(self):
        ptr = MyStruct()
        ptr.Command_String_A = "GetLocalSize".encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            base_addr = recv_struct.Command_int_A
            return base_addr
        else:
            return False
        return False
    def get_module_base(self,module_name):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetModuleBaseAddress".encode("utf8")
            ptr.Command_String_B = module_name.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False
    def get_module_from_function(self,module,function):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetModuleBaseFromFunction".encode("utf8")
            ptr.Command_String_B = module.encode("utf8")
            ptr.Command_String_C = function.encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False
    def get_all_module(self):
        all_module = []
        send_struct = MyStruct()
        send_struct.Command_String_A = "GetAllModule".encode("utf8")
        try:
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
            print(recv_count)
            if recv_count != 0:
                for index in range(0,recv_count):
                    dic = {"base": None, "entry": None, "name": None, "path": None, "size": None}
                    recv_buffer = self.sock.recv(536)
                    (base,entry,name,path,size) = struct.unpack("< q q 256s 260s i", recv_buffer)
                    decode_name = name.decode("utf8").replace('\0','')
                    decode_path = path.decode("utf8").replace('\0','')
                    dic.update({"base": base, "entry": entry, "name": decode_name, "path": decode_path, "size": size})
                    all_module.append(dic)

                return all_module
            else:
                return False
        except Exception:
            return False
    def get_module_from_import(self,module_name):
        all_module = []
        send_struct = MyStruct()
        send_struct.Command_String_A = "GetImport".encode("utf8")
        send_struct.Command_String_B = module_name.encode("utf8")
        try:
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
            if recv_count != 0:
                for index in range(0,recv_count):
                    dic = {"name": None, "iat_va": None, "iat_rva": None}
                    recv_buffer = self.sock.recv(528)
                    (name,iat_va,iat_rva) = struct.unpack("< 512s q q", recv_buffer)
                    decode_name = name.decode("utf8").replace('\0','')
                    dic.update({"name": decode_name, "iat_va": iat_va, "iat_rva": iat_rva})
                    all_module.append(dic)
                return all_module
            else:
                return False
        except Exception:
            return False
    def get_module_from_export(self,module_name):
        all_module = []
        send_struct = MyStruct()
        send_struct.Command_String_A = "GetExport".encode("utf8")
        send_struct.Command_String_B = module_name.encode("utf8")
        try:
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
            if recv_count != 0:
                for index in range(0,recv_count):
                    dic = {"name": None, "iat_va": None, "iat_rva": None}
                    recv_buffer = self.sock.recv(528)
                    (name,va,rva) = struct.unpack("< 512s q q", recv_buffer)
                    decode_name = name.decode("utf8").replace('\0','')
                    dic.update({"name": decode_name, "va": va, "rva": rva})
                    all_module.append(dic)
                return all_module
            else:
                return False
        except Exception:
            return False
    def get_section(self):
        all_section = []
        send_struct = MyStruct()
        send_struct.Command_String_A = "GetSection".encode("utf8")
        try:
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
            if recv_count != 0:
                for index in range(0,recv_count):
                    dic = {"addr": None, "name": None, "size": None}
                    recv_buffer = self.sock.recv(272)
                    (address,name,size) = struct.unpack("< q 256s q", recv_buffer)
                    decode_name = name.decode("utf8").replace('\0','')
                    dic.update({"addr": address, "name": decode_name, "size": size})
                    all_section.append(dic)
                return all_section
            else:
                return False
        except Exception:
            return False
    def push_stack(self,value):
        ptr = MyStruct()
        ptr.Command_String_A = "PushStack".encode("utf8")
        ptr.Command_int_A = value
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def pop_stack(self):
        ptr = MyStruct()
        ptr.Command_String_A = "PopStack".encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def peek_stack(self,index = 0):
        ptr = MyStruct()
        ptr.Command_String_A = "PeekStack".encode("utf8")
        ptr.Command_int_A = index

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return recv_struct.Command_int_A
        else:
            return False
        return False
    def get_thread_list(self):
        all_thread = []
        send_struct = MyStruct()
        send_struct.Command_String_A = "GetThreadList".encode("utf8")
        try:
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
            if recv_count != 0:
                for index in range(0,recv_count):
                    dic = {"thread_number": None, "thread_id": None, "thread_name": None, "local_base": None, "start_address": None}
                    recv_buffer = self.sock.recv(280)
                    (number,id,name,local_base,start_addr) = struct.unpack("< i i 256s q q", recv_buffer)
                    decode_name = name.decode("utf8").replace('\0','')
                    dic.update({"thread_number": number, "thread_id": id, "thread_name": decode_name, "local_base": local_base, "start_address": start_addr})
                    all_thread.append(dic)
                return all_thread
            else:
                return False
        except Exception:
            return False
    def get_process_handle(self):
        ptr = MyStruct()
        ptr.Command_String_A = "GetProcessHandle".encode("utf8")

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return recv_struct.Command_int_A
        else:
            return False
        return False
    def get_process_id(self):
        ptr = MyStruct()
        ptr.Command_String_A = "GetProcessID".encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return recv_struct.Command_int_A
        else:
            return False
        return False
    def get_teb_address(self,thread_id):
        ptr = MyStruct()
        ptr.Command_String_A = "GetTebAddress".encode("utf8")
        ptr.Command_int_A = thread_id

        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return recv_struct.Command_int_A
        else:
            return False
        return False
    def get_peb_address(self,process_id):
        ptr = MyStruct()
        ptr.Command_String_A = "GetPebAddress".encode("utf8")
        ptr.Command_int_A = process_id
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return recv_struct.Command_int_A
        else:
            return False
        return False
    def set_comment_notes(self,address,note):
        ptr = MyStruct()
        ptr.Command_String_A = "SetCommentNotes".encode("utf8")
        ptr.Command_int_A = address
        ptr.Command_String_B = note.encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def set_loger_output(self,log):
        ptr = MyStruct()
        ptr.Command_String_A = "SetLoger".encode("utf8")
        ptr.Command_String_B = log.encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
    def run_command_exec(self,cmd):
        ptr = MyStruct()
        ptr.Command_String_A = "RumCmdExec".encode("utf8")
        ptr.Command_String_B = cmd.encode("utf8")
        recv_struct = self.send_recv_struct(ptr)
        if recv_struct.Flag == 1:
            return True
        else:
            return False
        return False
