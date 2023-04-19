#keeping this for reference
#What the problem is: I need vtables from each mf class as a struct and I need them now!
#Well every class inherits from OSMetaClassBase, from there it trickles down. OSMetaClassBase contains 4 useful member vars
#a pointer to da supaclass
#a string ref to the name of the class
#class size 
#ref count which is fucking useless because the shit isn't even running, fuck am I gonna do with that
#What IS useful, a pointa to da supaclass, string ref to class name, and the class size


#idea for getting member variables for structs, look through each functions disassembly of that class and emulate it with unicorn
#log access to each member variables offsets to a list, sort the list by lowest to highest, use a foor loop from start to end with 4 step to keep consistent member var size + padding
#than create a member variable at each offset, with said padding inbetween 


import idaapi
import idc
import idautils
import codecs
import sys
import capstone
import unicorn
from capstone import * 
from unicorn import * 
from capstone.arm64 import *
import re
import math
import time
"""
Why would I want to make my life harder? Might as well make these global 
"""
capstone_instance = None
unicorn_instance = None 
IOKitBaseClasses = ["OSObject", "OSMetaClassBase", "OSData", "OSDictionary", "OSCollection", "OSSet", "OSMetaClass", "OSMetaClassBase"]
types_list = [
        "volatile", "unsigned", "register", "struct", "static", "unsigned __int8", "unsigned __int16", "unsigned __int32", "unsigned __int64", "unsigned __int128",
    "unsigned int32", "signed","unsigned int","union", "const", "void", "enum", "auto", 
    "bool", "char", "short", "int", "unsigned long","long", "float", "double",
    "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t",
    "uint32_t", "int64_t", "uint64_t", "int128_t", "uint128_t",
    "intptr_t", "uintptr_t", "intmax_t", "uintmax_t", "int_fast8_t",
    "int_fast16_t", "int_fast32_t", "int_fast64_t", "int_least8_t",
    "uint_least16_t", "uint_least32_t", "uint_least64_t", "uint_fast8_t",
    "uint_fast16_t", "uint_fast32_t", "uint_fast64_t", "uint_least8_t",
    "uint_least16_t", "uint_least32_t", "uint_least64_t",
    "SInt8", "UInt8", "SInt16", "UInt16", "SInt32", "UInt32",
    "SInt64", "UInt64", "task_t", "event_t",
    "_BOOL1", "_BOOL2", "_BOOL4", "__int8", "__int16", "__int32",
    "__int64", "__int128", "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD",
    "_TBYTE", "_UNKNOWN"
]
prev_defined = [
]
defined_types = [        
]
"""
class vtables: used to store information about a classes vtable
self.name: name of the vtable
self.members: each member of the vtable, could be functions or member vars
"""
class vtables:
    def __init__(self, name):
        self.name = name
        self.members = []
        self.size = size

    def append(member):
        if member == None:
            pass
        else:
            self.members.append(member)

"""
self.name: name of the class 
self.superClass: name of the superClass 
self.classSize: size of the class on it's own
self.classSizeInheritance: size of the class + size of the inherited classes
self.vtable: list of virtual table methods or member variables 
self.children: list of type IOClass that has objects representing each child class 
"""
class IOClass:
    def __init__(self, name, superClass, classSize, classSizeInheritance = 0):
        self.name = name #name of class
        self.superClass = superClass #pointer to the root/parent metaclass, can be none 
        self.classSize = classSize #size of the class without inherited members 
        self.classSizeInheritance = classSizeInheritance #size of the class with inherited members. Size of inherited class + size of current class
        self.vtable = None #pointer to vtable, remember that the first 0x10 bytes point to bullshit
        self.chidren = [] #list of all the children in the class 

    def add_child(self, child):
        self.children.append(child)
    def setName(self, name):
        self.name = name
    def getName(self):
        return self.name
    def setSuperClass(self, superClass):
        self.superClass = superClass
    def getSuperClass(self):
        return self.superClass
    def setSize(self, size):
        self.classSize = size
    def getSize(self):
        return self.classSize

    def getVtable(self):
        return self.vtable

    def setVtable(self, vtable_addr):
        self.vtable = vtable_addr


"""
this function initially iterates over all of the functions, with func being the start_ea/addr 
than it get's the name of the functioon, demangles it and checks if it's OSMetaClass constructor
if it is than return
"""
def get_osmeta_constructor():
    for func in list(idautils.Functions()):
        if idc.demangle_name(ida_funcs.get_func_name(func), idc.get_inf_attr(idc.INF_LONG_DN)) == "OSMetaClass::OSMetaClass(char const*, OSMetaClass const*, unsigned int)":
            return func #starting addr to the osmetaclass ctor

#return hex("".join([func for func in list(idautils.Functions()) if idc.demangle_name(ida_funcs.get_func_name(func), idc.get_inf_attr(idc.INF_LONG_DN)) == "OSMetaClass::OSMetaClass(char const*, OSMetaClass const*, unsigned int)"]))
def print_dict(d, indent=0):
    for key, value in d.items():
        print(' ' * indent + str(key))
        if isinstance(value, dict):
            print_dict(value, indent+4)
        else:
            print(' ' * (indent+4) + str(value))

def create_class_hierarchy(class_list):
    hierarchy = {}
    for child, parent in class_list:
        if parent not in hierarchy:
            hierarchy[parent] = {}
        hierarchy[parent][child] = {}
    return hierarchy

def fill_inheritance_gaps(hierarchy):
    for parent, children in hierarchy.items():
        for child, grand_children in children.items():
            if child in hierarchy:
                hierarchy[parent][child] = hierarchy[child]
    return hierarchy

#this takes in an instances of capstone and disassembles it
def disassemble_insc(capstone_instance, addr):
    return capstone_instance.disam(ida_bytes.get_dword(addr).to_bytes(4, byteorder="little"), addr)



"""
Phook Lore Entry:
    once upon a time, there was a magical group of elves called the realest mfs in the gang slime money money no kizzy ong fr 0 cap
    basically these elves made ARM64, but one thing these stupid elves decided was that in specific scenarios, man wtf is this shit nvm okay lemme restart

    Basically these are used to hold immediate values from registers just in case it's accessed via memory operands, if it is than the value is most likely being dereferenced so that means after the ADRP -> LDR calls, the value stored in the register
    operand will be set to 0 which will not give us the info we need! So this is here to hold the data at the register at the exact moment the LDR instruction is hit so we can yoink it before it goes to 0, cause who wants a 0 in life, imagine how
    you feel about having 0 hoes but now it's also 0 metaclass information too! double whammy fr 
"""
phook_reg = [0, 0, 0] 

def hook_invalid_uc(uc):
    print("[+] Invalid instruction hit")

def hook_insn_uc(uc, address, size, user_data):
    global capstone_instance
    global phook_reg
    src = 0
    offset = 0
    reg = 0
    #ins_bytes = list(capstone_instance.disasm(ida_bytes.get_dword(address).to_bytes(4, byteorder="little"), address))

    #instrs_bytes = uc.mem_read(address, size)
    if not capstone_instance.disasm(ida_bytes.get_dword(address).to_bytes(4, byteorder="little"), address): 
        print("[+] My brother this is an invalid line that could not be diassembled... inshallah very haram")
        return None
    x1 = uc.reg_read(arm64_const.UC_ARM64_REG_X1) #class name
    x2 = uc.reg_read(arm64_const.UC_ARM64_REG_X2) #super class
    w3 = uc.reg_read(arm64_const.UC_ARM64_REG_W3) #size of class 
    # ^^ these three registers are function arguments for a call to OSMetaClass::OSMetaClass(), if we can intercept these arguments during execution during emulation, we can get this info ez pz
    for instr in capstone_instance.disasm(ida_bytes.get_dword(address).to_bytes(4, byteorder="little"), address):
        if instr.mnemonic == "RETAB":
            print(f"[+] Allegedly reached the end of func at addr: 0x{hex(address)}") #in the case that we reach the end of the function, just in case emulator size constraints are sqrewed we quit
            printf(f"[+] 0x{hex(instr.address)}\t{instr.mnemonic}, {instr.op_str}") 
            uc.emu_stop()
        if instr.mnemonic == "bl":
            print(f"[+] This is where the function usefulness ends p much, all we needed was x1, x2, and w3, BYE BYE NOW: 0x{hex(address)}")
            print(f"[+] 0x{hex(instr.address)}\t{instr.mnemonic}, {instr.op_str}")
            uc.emu_stop()
        elif instr.mnemonic == "ldr":
            #print("[+] Hit a LDR instr...")
            #print(instr)
            for op in instr.operands:
                print(op.type, ARM64_OP_MEM)
                if op.type == ARM64_OP_MEM:
                    src = op.mem.base
                    offset = op.mem.disp
                elif op.type == ARM64_OP_REG:
                    reg = op.value.reg

                if op.type == ARM64_OP_MEM:
                    read_offset = uc.mem_read(address+offset, 8)
                    #print(read_offset)
                    read_offset_bytes = int.from_bytes(read_offset, byteorder = "little") 
                    if read_offset_bytes == 0 and src == ARM64_REG_X1:
                        phook_reg[0] = x1 + offset
                    elif read_offset_bytes == 0 and src == ARM64_REG_X2:
                        phook_reg[1] = x2 + offset
                    #print("[+] Fingers crossed every register was read :fingers_crossed:")

def unicorn_emulate(func_call_addr):
    global unicorn_instance
    global phook_reg
    true_start = ida_funcs.get_func(func_call_addr).start_ea #start addr pre byte alignment
    func_call_addr = ida_funcs.get_func(func_call_addr).end_ea
    start_addr = true_start 
    print(f"Start Pre: {hex(ida_funcs.get_func(func_call_addr).start_ea)}\nEnd Pre:{hex(ida_funcs.get_func(func_call_addr).end_ea)}")
    print(f"Start: {hex(start_addr)}\nEnd: {hex(func_call_addr)}\nResult of end-start: {func_call_addr-start_addr}")
    unicorn_instance.reg_write(arm64_const.UC_ARM64_REG_SP, func_call_addr + 0x400) #stack grows down so get end and add 0x400 to get the top of the stack
    unicorn_instance.mem_write(start_addr, ida_bytes.get_bytes(start_addr, func_call_addr-start_addr)) #update start to have new KB aligned address 
    #unicorn_instance.hook_add(UC_HOOK_CODE, hook_insn_uc, None, None, None) 
    unicorn_instance.hook_add(UC_HOOK_CODE, hook_insn_uc, begin = start_addr, end = func_call_addr)
    unicorn_instance.hook_add(UC_HOOK_INSN_INVALID, hook_invalid_uc)
    unicorn_instance.emu_start(start_addr, func_call_addr)
    x1 = unicorn_instance.reg_read(arm64_const.UC_ARM64_REG_X1)
    x2 = unicorn_instance.reg_read(arm64_const.UC_ARM64_REG_X2)
    w3 = unicorn_instance.reg_read(arm64_const.UC_ARM64_REG_W3)
    x1 = phook_reg[0] if x1==0 else x1
    x2 = phook_reg[1] if x2==0 else x2
    w3 = phook_reg[2] if w3==0 else w3
    return [x1,x2,w3] 


"""
For emulation, this is a last ditch effort essentially, what I need to do is first check if the vtable is public 
or not, the only reason I need to do that is because if it isn't public than the name and typing for the functions will be very off/return None, so what now?
We emulate! We know what class the vtable is for, so we can use that to get the constructor for that class, in the constructor, the addr for the vtable is loaded into reg X16 and offset by 10 in order to access presumably an allocation method, but we don't need that, we just need the address of the vtable which is calculated using an ADRL instruction meaning it uses the current instruction addr to calculate the location of the vtable, which we can do. Just like last time with phook_reg, when reading from ADRP, it's possible that 0 is returned because the value in X16 is caluclated with a dereference which does not store the memory after the operation so we need to yoink it asap, if we don't yoink it tho we'll default it to 0 and say we weren't swag enough to read from the reg"""

#Read up to ADRL instruction to X16 to grab the vtable which is offset from the current PC, try not to miss the dereference or else it will return garbage :(
def insc_hook_vtab(uc, address, size, user_data):
    global capstone_instance
    if not capstone_instance.disasm(ida_bytes.get_dword(address).to_bytes(4, byteorder="little"), address):
        print("[+] Could not grab the mf fucking uhhhhh the instruction uhhhhh guh")
    x16 = unicorn_instance.reg_read(UC_ARM64_REG_X16)
    for instr in capstone_instance.disasm(ida_bytes.get_dword(address).to_bytes(4, byteorder="little"), address):
        if instr.mnemonic == "retab":
            print(f"[+] Allegedly reached the end of func at addr: 0x{hex(address)}") #in the case that we reach the end of the function, just in case emulator size constraints are sqrewed we quit
            printf(f"[+] 0x{hex(instr.address)}\t{instr.mnemonic}, {instr.op_str}") 
            uc.emu_stop()
        elif instr.mnemonic == "adrl":
            vtab_addr = uc.reg_read(UC_ARM64_REG_X16)
            print(vtab_addr)

value_X16 = 0 #Global variable used to store the value of X16 in case dereference occurs and we read the reg value too late

def grab_vtable_addr(constructor_addr):
    global unicorn_instance
    global value_X16
    start_addr = ida_funcs.get_func(constructor_addr).start_ea
    final_addr = ida_funcs.get_func(constructor_addr).end_ea
    unicorn_instance.reg_write(UC_ARM64_REG_SP, final_addr + 0x400)
    unicorn_instance.mem_write(start_addr, ida_bytes.get_bytes(start_addr, final_addr - start_addr))
    unicorn_instance.hook_add(UC_HOOK_CODE, insc_hook_vtab, begin = start_addr, end = final_addr) 
    unicorn_instance.hook_add(UC_HOOK_INSN_INVALID, hook_invalid_uc)
    unicorn_instance.emu_start(start_addr, final_addr)
    X16 = unicorn_instance.reg_read(UC_ARM64_REG_X16)
    print(X16)


def grab_vtable_start(className):
    global unicorn_instance
    deref = 0 #used to grab vtable immediate in case a dereference happens
    new_name = className+"::"+className
    func_addr = 0
    for f in ida_funcs.Functions():
        if className in ida_funcs.get_func_name(f):
            func_addr = f
    true_start = ida_funcs.get_func(func_addr).start_ea
    true_end = ida_funcs.get_func(func_addr).end_ea

def var_generic_names(sig):
    # Split the signature into the function name and argument list
    match = re.match(r"^([\w\s*]+)\(([\w\s*,]*)\)$", sig)
    if match is None:
        return sig
    
    func_name, arg_list = match.groups()
    
    # Split the argument list into individual arguments
    args = arg_list.split(",")
    
    # Create a dictionary to keep track of generic parameter names
    generic_names = {}
    
    # Replace each argument with a generic name
    for i, arg in enumerate(args):
        # Get the argument type and name
        match = re.match(r"([\w\s*]+)([\w]+)?", arg.strip())
        if match is None:
            generic_name = f"v{i}"
        else:
            arg_type, arg_name = match.groups()
            if arg_name is not None:
                generic_name = arg_name
            elif arg_type in generic_names:
                # Reuse an existing generic name for this type
                generic_name = generic_names[arg_type]
            else:
                # Create a new generic name for this type
                generic_name = f"v{len(generic_names)}"
                generic_names[arg_type] = generic_name
                
        # Update the argument with the generic name
        args[i] = f"{arg_type}{generic_name}"
    
    # Combine the function name and updated argument list to create the new signature
    new_sig = f"{func_name}({', '.join(args)})"
    return new_sig



"""
What's the end goal for this? 
Let's say you have the current definition
['void __cdecl(OSObject *__hidden this)', 'IOAVControllerAddDeviceCompletion::~IOAVControllerAddDeviceCompletion()']
The final result should be void (__cdecl *DTOR_IOAvControllerAddDeviceCompletion)(OSObject* __hidden this)
In theory, what are the patterns I should be searching for. Definetly for __ so I can grab the calling convetion of the function,
another thing I should look out for is templates, so <> would be an interesting pattern, lambdas are in the form of function pointers, so look for function pointer patterns as well such as (*). In the second string of the list, I should search for ~ so I know it's a DTOR.
"""
def parse_func(func_info):
    print(func_info)
    if ida_funcs.get_func_name(func_info[2]) == None: 
        return ""
    elif "sub_" in ida_funcs.get_func_name(func_info[2]):
        print(func_info)
        final_type = ""
        final_type += "__int64 (__fastcall *" 
        final_type += idc.demangle_name(ida_funcs.get_func_name(func_info[2]), True) if idc.demangle_name(ida_funcs.get_func_name(func_info[2]), True) != None else ida_funcs.get_func_name(func_info[2]) + ")" +"(void)"
        print("Final vfunc type: ", final_type, "\n")
        if "~" in final_type:
            final_type.replace("~", "DTOR_")
        final_type += ";"
        return final_type
    elif func_info[1] == None and func_info[0] != None:
        final_type = ""
        func_type = func_info[0] 
        func_name = idc.demangle_name(ida_funcs.get_func_name(func_info[2]), True) if idc.demangle_name(ida_funcs.get_func_name(func_info[2]), True) != None else ida_funcs.get_func_name(func_info[2]) 
        if " " in func_info[0]: 
            final_type += re.search("^[^\\(]+[\s|*]", func_info[0]).group() + "("  #grabs the return type
            final_type += re.search("__fastcall|__stdcall|__cdecl|__noreturn|__usercall", func_info[0]).group() + " *"
        else:
            final_type += func_info[0][0:func_info[0].find("(")] + "("
            final_type += "__fastcall *"
        if "::" not in func_name:
            final_type += func_name.split("(")[0] + ")"
        else:
            final_type += re.search("(?<=::)[^()]+", func_name).group() + ")"
        final_type += re.search("\((.*)\)", func_type).group()
        if "~" in final_type:
            final_type.replace("~", "DTOR_")
        final_type += ";"
        print("Final vfunc type : ", final_type, "\n")
        return final_type
    elif func_info[0] == None and func_info[1] != None:
        final_type = ""
        func_type = get_type(func_info[2])
        func_name = func_info[1]
        final_type += "__int64 (__fastcall *"
        if "::" not in func_name:
            final_type += func_name.split("(")[0] + ")"
        else:
            final_type += re.search("(?<=::)[^()]+", func_name).group() + ")"
        final_type += re.search("\((.*)\)", func_name).group()

    elif func_info[0] == None and func_info[1] == None:
        final_type = ""
        func_name = ida_funcs.get_func_name(func_info[2])
        final_type += func_name[0:func_name.find("(")] + "(" if "(" in func_name else "__int64 (" 
        final_type += "__fastcall* "
        if "::" not in func_name:
            final_type += func_name.split("(")[0] + ")"
        else:
            final_type += re.search("(?<=::)[^()]+", func_name).group() + ")"
        final_type += re.search("\((.*)\)", func_name).group()
        if "~" in final_type:
            final_type.replace("~", "DTOR_")
        final_type += ";"
        print("Final vfunc type : ", final_type, "\n")
        return final_type
    elif "vtable" in func_info[1]: #or (f[0] == None and f[1] == None) or ("vtbl" in f[1] or "vtbl" in f[1] or "vtable" in f[0] or "vtbl" in f[0]) or " " not in f[0] or " " not in f[1]:
        names = []
        true_addr = func_info[2] + 16 #this and below will be parse the vtable into the current vtable because the global pointer is for some reason incapable of understanding that the 
        final_type = ""
        func_type = get_type(ida_bytes.get_qword(true_addr))
        func_name = idc.demangle_name(ida_bytes.get_qword(true_addr), idc.get_inf_attr(idc.INF_LONG_DN))
        while true_addr != 0:
            if " " in func_type: 
                final_type += re.search("^[^\\(]+[\s|*]", func_type).group() + "("  #grabs the return type
                final_type += re.search("__fastcall|__stdcall|__cdecl|__noreturn|__usercall", func_type).group() + " *"
            else:
                final_type += func_type[0:func_type.find("(")] + "("
                final_type += "__fastcall"
            if "::" not in func_name:
                final_type += func_name.split("(")[0] + ")"
            else:
                final_type += re.search("(?<=::)[^()]+", func_info[1]).group() + ")"
            final_type += re.search("\((.*)\)", func_info[0]).group()
            print("Final vfunc type : ", final_type, "\n")
            names.append(final_type)
            true_addr += 8
        return names
    else:    
        print(func_info)
        final_type = "" #creates the empty string 
        if " " in func_info[0][0:func_info[0].find("(")]:
            final_type += re.search("^[^\\(]+[\s|*]", func_info[0]).group() + "("  #grabs the return type
            final_type += re.search("__fastcall|__stdcall|__cdecl|__noreturn|__usercall", func_info[0]).group() + " *"
        else:
            final_type += func_info[0][0:func_info[0].find("(")] + "("
            final_type += "__fastcall *"
        if "::" not in func_info[1]:
            final_type += func_info[1].split("(")[0]
            final_type += ")"
        else:
            final_type += re.search("(?<=::)[^()]+", func_info[1]).group()
            final_type += ")"
        final_type += re.search("\((.*)\)", func_info[0]).group()  #grabs the parameters 
        print("Final type: ", final_type, "\n")
        return final_type
    print("Final vfunc type: " , final_type, "\n")
    return final_type
            

#Essentially was meant to just remove namespace operators, in hindsight this is useless
def clean_string(s):
    pattern = re.compile(r"\b\w+::(?=\S)")
    cleaned_sig = re.sub(pattern, "", s)
    return cleaned_sig

#Extract function name
def extract_function_name(input_string):
    # Regex pattern to match function names
    pattern = r'\* *\(*([\w]+)\)'
    match = re.search(pattern, input_string)
    if match:
        return match.group(1)
    return None

#Extracts parameter types to create local types 

def extract_parameter_types(func_str):
    # Find the last pair of parentheses
    matches = list(re.finditer(r'\(([^()]*)\)', func_str))
    if not matches:
        return []

    # Extract the parameter string between the last pair of parentheses
    params_str = matches[-1].group(1)

    # Split the parameter string by commas
    params = params_str.split(',')

    # Define a regular expression pattern to match parameter types
    type_pattern = re.compile(r"[\w\s:*<>]+")

    # Extract parameter types from each parameter
    param_types = []
    for param in params:
        if param.strip():
            param_type_match = type_pattern.match(param.strip())
            if param_type_match:
                param_type = param_type_match.group(0).strip()
                param_type = re.sub(r'[*]|__hidden|const|__struct_ptr', '', param_type).strip()
                # Remove parameter names
                param_type = re.sub(r'\s\w+$', '', param_type)
                param_types.append(param_type)

    return param_types


def local_type_exists(type_name):
    for i in range(1, idc.get_ordinal_qty()):
        current_type_name = idc.get_numbered_type_name(i)
        if type_name == current_type_name:
            return True
    return False

def handle_super_class(class_dict, super_class_obj, mbrs_struct, IOKitBaseClasses, depth = 0):
    offset = 0
    if super_class_obj:
        super_class_name = super_class_obj.getName()
        parent_class_name = super_class_obj.getSuperClass()
        idaapi.add_struc_member(mbrs_struct, "base_class_ptr", 0, idc.FF_QWORD, None, 8)
        base_ptr = idaapi.get_member_by_name(mbrs_struct, "base_class_ptr")

        tinfo = idaapi.tinfo_t()
        til = idaapi.cvar.idati

        if parent_class_name:
            if parent_class_name not in IOKitBaseClasses:
                idaapi.add_struc_member(mbrs_struct, "base_class_ptr", 0, idc.FF_QWORD, None, 8)
                base_ptr = idaapi.get_member_by_name(mbrs_struct, "base_class_ptr")
                base_class_decl = f"struct {parent_class_name}_mbrs;"
                idc.set_local_type(-1, base_class_decl, idaapi.PT_TYP)
                base_class_decl = f"struct {parent_class_name}_mbrs base_class_ptr;"
                print(f"Base Class: {base_class_decl}")
                idaapi.parse_decl(tinfo, til, base_class_decl, idaapi.PT_TYP)
                idaapi.set_member_tinfo(mbrs_struct, base_ptr, 0, tinfo, idaapi.TINFO_DEFINITE)
                offset += 8
            else:
                idaapi.add_struc_member(mbrs_struct, "base_class_ptr", 0, idc.FF_QWORD, None, 8)
                base_ptr = idaapi.get_member_by_name(mbrs_struct, "base_class_ptr")
                base_class_decl = f"struct {parent_class_name} base_class_ptr;"
                print(f"Base Class: {base_class_decl}")
                idaapi.parse_decl(tinfo, til, base_class_decl, idaapi.PT_TYP)
                idaapi.set_member_tinfo(mbrs_struct, base_ptr, 0, tinfo, idaapi.TINFO_DEFINITE)
                offset += 8
        else:
            print("No parent class!")

        
        #super_super_class_obj = class_dict.get(parent_class_name)
        #if super_super_class_obj:
        #    handle_super_class(class_dict, super_super_class_obj, mbrs_struct, IOKitBaseClasses, depth+1)

        # Calculate the padding size
        child_sz = super_class_obj.classSize
        parent_sz = super_class_obj.classSizeInheritance - child_sz
        adding_size = (child_sz - 8) - (parent_sz - 8)

        if adding_size > 0:
            padding_var_start = idaapi.add_struc_member(mbrs_struct, "padding_start_guard", offset, idc.FF_BYTE, None, 1)
            padding_var = idaapi.add_struc_member(mbrs_struct, "padding", offset+1, idc.FF_BYTE, None, adding_size)
            padding_var_end = idaapi.add_struc_member(mbrs_struct, "padding_end_guard", 8 + adding_size, idc.FF_BYTE, None, 1)

        #if depth == 1:
        #    return


def check_type(type_name):
    tinfo = idaapi.tinfo_t()
    til = idaapi.cvar.idati
    full_type = f"struct {type_name} var;"
    ret = idaapi.parse_decl(tinfo, til, full_type, idaapi.PT_TYP)
    return ret is None


def struct_alignment(struc_name):
    struc_id = idaapi.get_struc_id(struc_name)
    struc_obj = idaapi.get_struc(struc_id)
    struc_obj.atyp = 0x8
    return ida_struct.set_struc_align(struc_obj, 3)

#tuple structure of name: (ea, name)
def create_structs(class_dict, inherits_dict):
    vtab_decls = {} #stores the function name and type in list format [func_type, func_name] 
    vtab_size = {} #used to store the size of each vtable
    ea = 0
    for name in idautils.Names():
        vtab_name = idc.demangle_name(name[1], idc.get_inf_attr(idc.INF_LONG_DN)) if idc.demangle_name(name[1], idc.get_inf_attr(idc.INF_LONG_DN)) != None else name[1]
        if "vtable for" in vtab_name and vtab_name != None and "::metaclass" not in vtab_name.lower() and (ida_name.is_public_name(name[0])): # or constructor in Names()): 
            vtab_name = vtab_name.replace("`","").replace("vtable for", "").replace("'","")
            print(vtab_name)
            vtab_decls[vtab_name] = []
            vtab_size[vtab_name] = 0
            true_addr = name[0] + 16
            ea = ida_bytes.get_qword(true_addr) 
            vtab_decls[vtab_name].append([get_type(ea), idc.demangle_name(get_name(ea), idc.get_inf_attr(idc.INF_LONG_DN)), ea])
            print("True Addr: ", hex(true_addr), "ea: ", (ea), "size: ", vtab_size[vtab_name])
            while ida_bytes.get_qword(true_addr+8) != 0:
                true_addr+=8
                ea = ida_bytes.get_qword(true_addr)
                vtab_size[vtab_name]+=8
                print("True Addr: ", hex(true_addr), "ea: ", (ea), "size: ", vtab_size[vtab_name])
                vtab_decls[vtab_name].append([get_type(ida_bytes.get_qword(true_addr)), idc.demangle_name(get_name(ida_bytes.get_qword(true_addr)), idc.get_inf_attr(idc.INF_LONG_DN)), ea])
            vtab_size[vtab_name]-=4
        elif "vtable for" in vtab_name and vtab_name != None and "::metaclass" not in vtab_name.lower() and ida_name.is_public_name(name[0]) == False: #and constructor not in Names():
            vtab_name = vtab_name.replace("`","").replace("vtable for", "").replace("'","")
            vtab_decls[vtab_name] = []
            vtab_size[vtab_name] = 0
            if idc.demangle_name(name[1], idc.get_inf_attr(idc.INF_LONG_DN)):
                print(name[0],idc.demangle_name(name[1], True), "We out here!\n")
                true_addr = ida_bytes.get_qword(name[0]) if ida_bytes.get_qword(name[0]) != 0 else name[0]
                true_addr+=16
                print(true_addr)
                while ida_bytes.get_qword(true_addr+8) != 0:
                    ea = ida_bytes.get_qword(true_addr)
                    vtab_size[vtab_name]+=8
                    vtab_decls[vtab_name].append([get_type(ida_bytes.get_qword(true_addr)), idc.demangle_name(get_name(ida_bytes.get_qword(true_addr)), idc.get_inf_attr(idc.INF_LONG_DN)), ea])
                    true_addr+=8
                vtab_size[vtab_name]-=4
            print("\n"*30)
    """
    for key in class_dict:
        #struct_name = key.replace("'", " ").split(" ")[2]
        #struct_name = class_dict[key].getName()[2:].replace("'","")
        struct_name = class_dict[key].getName().replace("'", "").replace("`", "")
        if struct_name.startswith("vtable for"):
            struct_name = struct_name[10:]
        add_struc(-1, struct_name, False)
        add_struc(-1, struct_name+"_vtbl", False)
        add_struc(-1, struct_name+"_mbrs", False)
    """
    for key in class_dict:
        #if key not in list(class_dict.keys()):
        #    continue
        prev_defined.append(key)
        curr_members = {}
        offset = 16
        prev_type = ""
        struct_name = key
        add_struc(-1, struct_name, False) 
        if key not in IOKitBaseClasses:
            add_struc(-1, struct_name+"_vtbl", False)
            fields_name = f"{struct_name}::fields"
            add_struc(-1, fields_name, False)
            fields_name = f"struct {struct_name}::fields;"
            idc.set_local_type(-1, fields_name, idaapi.PT_TYP)
            fields_name = f"typedef struct {struct_name}::fields {struct_name}_mbrs;"
            idc.set_local_type(-1, fields_name, idaapi.PT_TYP)
            struct_alignment(struct_name)
            struct_alignment(struct_name+"_vtbl")
            struct_alignment(struct_name+"::fields")
        struc = idaapi.get_struc(idaapi.get_struc_id(struct_name+"_vtbl"))
        class_struc = idaapi.get_struc(idaapi.get_struc_id(struct_name)) 
        mbrs_struct = idaapi.get_struc(idaapi.get_struc_id(struct_name+"::fields"))
        if key not in vtab_decls:
            add_member = idaapi.add_struc_member(struc, "thisOffset", 0, idc.FF_QWORD, None, 8) #Creates a struct member in the vtable struct for the this ptr 
            struct_member = idaapi.get_member_by_name(struc, "thisOffset") 
            tinfo = idaapi.tinfo_t()
            idaapi.parse_decl(tinfo, idaapi.cvar.idati, "__int64 thisOffset;", idaapi.PT_TYP)
            idaapi.set_member_tinfo(struc, struct_member, 0, tinfo, idaapi.TINFO_DEFINITE)
            add_member = idaapi.add_struc_member(struc, "rtti", 8, idc.FF_QWORD, None, 8) #Creates a struct member in the vtable struct for the runtime type information 
            struct_member = idaapi.get_member_by_name(struc, "rtti")
            tinfo = idaapi.tinfo_t()
            idaapi.parse_decl(tinfo, idaapi.cvar.idati, "void* rtti;", idaapi.PT_TYP)
            idaapi.set_member_tinfo(struc, struct_member, 8, tinfo, idaapi.TINFO_DEFINITE)
            class_obj = class_dict[struct_name] #Get the current class object
            super_class_name = class_obj.getSuperClass() #get super class name
            super_class_obj = class_dict[super_class_name] if super_class_name in list(class_dict.keys()) else "" #given super class name, get the obj for the super class
            idaapi.add_struc_member(class_struc, "__vftable", 0, idc.FF_QWORD, None, 8) #create a struct member for the vtable
            struc_mem = idaapi.get_member_by_name(class_struc, "__vftable") #grab the vtable member variable
            tinfoo = idaapi.tinfo_t() #tinfo variable
            struc_member_name = struct_name+"_vtbl" #this is the
            struc_member_name += "* __vftable;"
            print("Struct name: ",struct_name)
            idaapi.parse_decl(tinfoo, idaapi.cvar.idati, struc_member_name, idaapi.PT_VAR)
            idaapi.set_member_tinfo(class_struc, struc_mem, 0, tinfoo, idaapi.TINFO_DEFINITE)
            mbrs_size = class_dict[struct_name].getSize() if struct_name in list(class_dict.keys()) else 200
            idaapi.add_struc_member(class_struc, "mbrs", 8, idc.FF_QWORD, None, mbrs_size)
            mbr_struc_member = idaapi.get_member_by_name(class_struc, "mbrs")
            member_name = f"struct {struct_name} mbrs;" if struct_name in IOKitBaseClasses else f"struct {struct_name}_mbrs mbrs;"
            tinfo = idaapi.tinfo_t()
            til = idaapi.cvar.idati
            print(f"Member name: {member_name}") 
            idaapi.parse_decl(tinfo, til, member_name, idaapi.PT_TYP)
            #idaapi.parse_decl(type_info, idaapi.cvar.idati, member_name, idaapi.PT_TYP)
            idaapi.set_member_tinfo(class_struc, mbr_struc_member, 8, tinfo, idaapi.TINFO_DEFINITE)
            print("Member class size", mbrs_size)
            #if struct_name in list(class_dict.keys()) or demangle_name(get_name(class_dict[struct_name].getSuperClass()),idc.get_inf_attr(idc.INF_LONG_DN)) in list(class_dict.keys()): 
            if super_class_obj != "" and super_class_obj != None: 
                handle_super_class(class_dict, super_class_obj, mbrs_struct, IOKitBaseClasses) 

        else:
            print(f"[+] VTable Name: {key}\n[+] Stuff In The Dictionary ig lol: {vtab_decls[key]}")
            print("\n"*5)
            tinfo = idaapi.tinfo_t()
            til = idaapi.cvar.idati
            local_type_details = f"struct {struct_name};"
            #type_decl = idaapi.parse_decl(tinfo, til, local_type_details, ida_typeinf.PT_TYP)
            index = idc.set_local_type(-1, local_type_details, ida_typeinf.PT_TYP)
            tinfo = idaapi.tinfo_t()
            til = idaapi.cvar.idati
            #local_type_details = f"struct {struct_name}Mbrs;"
            #idaapi.parse_decl(tinfo, til, local_type_details, ida_typeinf.PT_TYP)
            #idc.set_local_type(-1, local_type_details, ida_typeinf.PT_TYP)
            #Problems I need to solve
            #Duplicate Names of Member Vars/Duplicate Types
            #C++ Type Parsing using Siguzas method he told me
            #Objective C somehow being in the fucking kernel
            add_member = idaapi.add_struc_member(struc, "thisOffset", 0, idc.FF_QWORD, None, 8) #Creates a struct member in the vtable struct for the this ptr 
            struct_member = idaapi.get_member_by_name(struc, "thisOffset") 
            tinfo = idaapi.tinfo_t()
            idaapi.parse_decl(tinfo, idaapi.cvar.idati, "__int64 thisOffset;", idaapi.PT_TYP)
            idaapi.set_member_tinfo(struc, struct_member, 0, tinfo, idaapi.TINFO_DEFINITE)
            add_member = idaapi.add_struc_member(struc, "rtti", 8, idc.FF_QWORD, None, 8) #Creates a struct member in the vtable struct for the runtime type information 
            struct_member = idaapi.get_member_by_name(struc, "rtti")
            tinfo = idaapi.tinfo_t()
            idaapi.parse_decl(tinfo, idaapi.cvar.idati, "void* rtti;", idaapi.PT_TYP)
            idaapi.set_member_tinfo(struc, struct_member, 8, tinfo, idaapi.TINFO_DEFINITE)
            for func in vtab_decls[key]:
                func_type = parse_func(func)
                print("Func Type: ", func_type)
                if not isinstance(func_type, list) and len(func_type) > 0:
                    if "~" in func_type:
                        func_type = func_type.replace("~", "DTOR_")
                    func_name = extract_function_name(func_type) 
                    if func_name not in curr_members:
                        curr_members[func_name] = 0
                    else:
                        curr_members[func_name] += 1
                        func_name = f"{func_name}_{curr_members[func_name]}"
                    #Adds semicolon if not previously added
                    if ";" not in func_type:
                        func_type += ";"
                    #Comments below explain this case too
                    if "_0" in func_type:
                        func_type = func_type.replace("_0", "")
                    #Edge case again, although this can be fixed as well as ^^ with typedefs 
                    #typedef <name_of_class> <name_of_class>_1;
                    if "_1" in func_type:
                        func_type = func_type.replace("_1", "")
                    if "::*" in func_type:
                        func_type = func_type.replace("::*", "*")
                    #_vm_map seems to be weird edge case, created a typedef for it
                    #typedef vm_map_t _vm_map;
                    if "_vm_map" in func_type:
                        tinfo = idaapi.tinfo_t()
                        til = idaapi.cvar.idati
                        local_type_details = f"typedef vm_map_t _vm_map;"
                        type_decl = idaapi.parse_decl(tinfo, til, local_type_details, ida_typeinf.PT_TYP)
                        if type_decl:
                            index = idc.set_local_type(-1, local_type_details, ida_typeinf.PT_TYP)
                            if index != -1:
                                print(f"Successfully added local type: {local_type_details}")
                    print(f"Func Type before processing: {func_type}")
                    #func_type = var_generic_names(func_type)
                    # First, define local types for all the template parameters
                    if "<" in func_type and ">" in func_type:
                        template_type = func_type[:func_type.find(">") + 1]
                        template_type_cleaned = template_type.replace("<", "_").replace(">", "")
                        temp_type = template_type_cleaned.split("_")[1]
                        temp_type_str = f"struct {temp_type};"
                        print(f"Parameter Type: {temp_type_str}")
                        result = idc.set_local_type(-1, temp_type_str, ida_typeinf.PT_TYP)
                        print(f"Result for parameter type: {result}")

    # Then, create the typedef using the previously defined template parameter types
                    if "<" in func_type and ">" in func_type:
                        local_type_details = f"typedef struct {temp_type} *{template_type_cleaned};"
                        print(f"Template type: {local_type_details}")
                        result = idc.set_local_type(-1, local_type_details, ida_typeinf.PT_TYP)
                        print(f"Result for template type: {result}")

                        func_type = func_type.replace(template_type, template_type_cleaned)
                    print(f"Func Type after processing: {func_type}")
                    parameter_list = extract_parameter_types(func_type)
                    print(parameter_list)
                    for param in parameter_list:
                        if param in types_list or param in defined_types or local_type_exists(param) == True:
                            print("Existing Param: ", param)
                            continue
                        else:
                            temp_param = param
                            if "const" in temp_param:
                                temp_param = temp_param.replace("const", "")
                            if "*" in param:
                                temp_param = temp_param.replace("*","")
                            local_type_details = f"struct {temp_param};"
                            print("Local Type: ", local_type_details)
                            #type_decl = idaapi.parse_decl(tinfo, til, local_type_details, ida_typeinf.PT_TYP)
                            index = idc.set_local_type(-1, local_type_details, idaapi.PT_TYP)
                            print(f"Local Type: {local_type_details}\nIndex: {index} << if this is 0 you fucked up </3")
                            defined_types.append(temp_param)
                    print(func_type)
                    add_member = idaapi.add_struc_member(struc, func_name, offset, idc.FF_QWORD, None, 8)
                    struct_member = idaapi.get_member_by_name(struc, func_name)
                    tinfo = idaapi.tinfo_t()
                    til = idaapi.cvar.idati
                    idaapi.parse_decl(tinfo, til, func_type, idaapi.PT_TYP)
                    idaapi.set_member_tinfo(struc, struct_member, offset, tinfo, idaapi.TINFO_DEFINITE)
                    prev_type = func_type
                    offset+=8
                else:
                    print("Type: ", func_type)
            #Adds main struct
            class_obj = class_dict[struct_name] #Get the current class object
            super_class_name = class_obj.getSuperClass() #get super class name
            super_class_obj = class_dict[super_class_name] if super_class_name in list(class_dict.keys()) else "" #given super class name, get the obj for the super class
            idaapi.add_struc_member(class_struc, "__vftable", 0, idc.FF_QWORD, None, 8) #create a struct member for the vtable
            struc_mem = idaapi.get_member_by_name(class_struc, "__vftable") #grab the vtable member variable
            tinfoo = idaapi.tinfo_t() #tinfo variable
            struc_member_name = struct_name+"_vtbl" #this is the
            struc_member_name += "* __vftable;"
            print("Struct name: ",struct_name)
            idaapi.parse_decl(tinfoo, idaapi.cvar.idati, struc_member_name, idaapi.PT_VAR)
            idaapi.set_member_tinfo(class_struc, struc_mem, 0, tinfoo, idaapi.TINFO_DEFINITE)
            print("Here One")
            #struc_mem = idaapi.get_member_by_name(class_struc, "m")
            #struc_member_name = struct_name+"_mbrs m;"
            #tinfoo = idaapi.tinfo_t()
            #idaapi.parse_decl(tinfoo, idaapi.cvar.idati, struc_member_name, idaapi.PT_VAR)
            #idaapi.set_member_tinfo(class_struc, struc_mem, 8, tinfoo, idaapi.TINFO_DEFINITE)
            #mbrs_size = vtab_size[key] #if "<" not in struct_name else vtab_size["`vtable for'"+struct_name.replace("_vtbl","")[0:struct_name.find("<")]] 
            mbrs_size = class_dict[struct_name].getSize() if struct_name in list(class_dict.keys()) else 200
            idaapi.add_struc_member(class_struc, "mbrs", 8, idc.FF_QWORD, None, mbrs_size)
            mbr_struc_member = idaapi.get_member_by_name(class_struc, "mbrs")
            member_name = f"struct {struct_name} mbrs;" if struct_name in IOKitBaseClasses else f"struct {struct_name}_mbrs mbrs;"
            tinfo = idaapi.tinfo_t()
            til = idaapi.cvar.idati
            print(f"Member name: {member_name}") 
            idaapi.parse_decl(tinfo, til, member_name, idaapi.PT_TYP)
            #idaapi.parse_decl(type_info, idaapi.cvar.idati, member_name, idaapi.PT_TYP)
            idaapi.set_member_tinfo(class_struc, mbr_struc_member, 8, tinfo, idaapi.TINFO_DEFINITE)
            print("Member class size", mbrs_size)
            #if struct_name in list(class_dict.keys()) or demangle_name(get_name(class_dict[struct_name].getSuperClass()),idc.get_inf_attr(idc.INF_LONG_DN)) in list(class_dict.keys()): 
            if super_class_obj != "" and super_class_obj != None: 
               handle_super_class(class_dict, super_class_obj, mbrs_struct, IOKitBaseClasses) 
        for key in class_dict:
            #if key not in list(class_dict.keys()):
            #    continue
            if key in prev_defined:
                continue
            curr_members = {}
            offset = 16
            prev_type = ""
            struct_name = key
            add_struc(-1, struct_name, False) 
            if key not in IOKitBaseClasses:
                add_struc(-1, struct_name+"_vtbl", False)
                fields_name = f"{struct_name}::fields"
                add_struc(-1, fields_name, False)
                fields_name = f"struct {struct_name}::fields;"
                idc.set_local_type(-1, fields_name, idaapi.PT_TYP)
                fields_name = f"typedef struct {struct_name}::fields {struct_name}_mbrs;"
                idc.set_local_type(-1, fields_name, idaapi.PT_TYP)
                struct_alignment(struct_name)
                struct_alignment(struct_name+"_vtbl")
                struct_alignment(struct_name+"::fields")
            struc = idaapi.get_struc(idaapi.get_struc_id(struct_name+"_vtbl"))
            class_struc = idaapi.get_struc(idaapi.get_struc_id(struct_name)) 
            mbrs_struct = idaapi.get_struc(idaapi.get_struc_id(struct_name+"::fields"))
            if key not in vtab_decls:
                add_member = idaapi.add_struc_member(struc, "thisOffset", 0, idc.FF_QWORD, None, 8) #Creates a struct member in the vtable struct for the this ptr 
                struct_member = idaapi.get_member_by_name(struc, "thisOffset") 
                tinfo = idaapi.tinfo_t()
                idaapi.parse_decl(tinfo, idaapi.cvar.idati, "__int64 thisOffset;", idaapi.PT_TYP)
                idaapi.set_member_tinfo(struc, struct_member, 0, tinfo, idaapi.TINFO_DEFINITE)
                add_member = idaapi.add_struc_member(struc, "rtti", 8, idc.FF_QWORD, None, 8) #Creates a struct member in the vtable struct for the runtime type information 
                struct_member = idaapi.get_member_by_name(struc, "rtti")
                tinfo = idaapi.tinfo_t()
                idaapi.parse_decl(tinfo, idaapi.cvar.idati, "void* rtti;", idaapi.PT_TYP)
                idaapi.set_member_tinfo(struc, struct_member, 8, tinfo, idaapi.TINFO_DEFINITE)
                class_obj = class_dict[struct_name] #Get the current class object
                super_class_name = class_obj.getSuperClass() #get super class name
                super_class_obj = class_dict[super_class_name] if super_class_name in list(class_dict.keys()) else "" #given super class name, get the obj for the super class
                idaapi.add_struc_member(class_struc, "__vftable", 0, idc.FF_QWORD, None, 8) #create a struct member for the vtable
                struc_mem = idaapi.get_member_by_name(class_struc, "__vftable") #grab the vtable member variable
                tinfoo = idaapi.tinfo_t() #tinfo variable
                struc_member_name = struct_name+"_vtbl" #this is the
                struc_member_name += "* __vftable;"
                print("Struct name: ",struct_name)
                idaapi.parse_decl(tinfoo, idaapi.cvar.idati, struc_member_name, idaapi.PT_VAR)
                idaapi.set_member_tinfo(class_struc, struc_mem, 0, tinfoo, idaapi.TINFO_DEFINITE)
                mbrs_size = class_dict[struct_name].getSize() if struct_name in list(class_dict.keys()) else 200
                idaapi.add_struc_member(class_struc, "mbrs", 8, idc.FF_QWORD, None, mbrs_size)
                mbr_struc_member = idaapi.get_member_by_name(class_struc, "mbrs")
                member_name = f"struct {struct_name} mbrs;" if struct_name in IOKitBaseClasses else f"struct {struct_name}_mbrs mbrs;"
                tinfo = idaapi.tinfo_t()
                til = idaapi.cvar.idati
                print(f"Member name: {member_name}") 
                idaapi.parse_decl(tinfo, til, member_name, idaapi.PT_TYP)
                #idaapi.parse_decl(type_info, idaapi.cvar.idati, member_name, idaapi.PT_TYP)
                idaapi.set_member_tinfo(class_struc, mbr_struc_member, 8, tinfo, idaapi.TINFO_DEFINITE)
                print("Member class size", mbrs_size)
                #if struct_name in list(class_dict.keys()) or demangle_name(get_name(class_dict[struct_name].getSuperClass()),idc.get_inf_attr(idc.INF_LONG_DN)) in list(class_dict.keys()): 
                if super_class_obj != "" and super_class_obj != None: 
                    handle_super_class(class_dict, super_class_obj, mbrs_struct, IOKitBaseClasses) 

            else:
                print(f"[+] VTable Name: {key}\n[+] Stuff In The Dictionary ig lol: {vtab_decls[key]}")
                print("\n"*5)
                tinfo = idaapi.tinfo_t()
                til = idaapi.cvar.idati
                local_type_details = f"struct {struct_name};"
                #type_decl = idaapi.parse_decl(tinfo, til, local_type_details, ida_typeinf.PT_TYP)
                index = idc.set_local_type(-1, local_type_details, ida_typeinf.PT_TYP)
                tinfo = idaapi.tinfo_t()
                til = idaapi.cvar.idati
                #local_type_details = f"struct {struct_name}Mbrs;"
                #idaapi.parse_decl(tinfo, til, local_type_details, ida_typeinf.PT_TYP)
                #idc.set_local_type(-1, local_type_details, ida_typeinf.PT_TYP)
                #Problems I need to solve
                #Duplicate Names of Member Vars/Duplicate Types
                #C++ Type Parsing using Siguzas method he told me
                #Objective C somehow being in the fucking kernel
                add_member = idaapi.add_struc_member(struc, "thisOffset", 0, idc.FF_QWORD, None, 8) #Creates a struct member in the vtable struct for the this ptr 
                struct_member = idaapi.get_member_by_name(struc, "thisOffset") 
                tinfo = idaapi.tinfo_t()
                idaapi.parse_decl(tinfo, idaapi.cvar.idati, "__int64 thisOffset;", idaapi.PT_TYP)
                idaapi.set_member_tinfo(struc, struct_member, 0, tinfo, idaapi.TINFO_DEFINITE)
                add_member = idaapi.add_struc_member(struc, "rtti", 8, idc.FF_QWORD, None, 8) #Creates a struct member in the vtable struct for the runtime type information 
                struct_member = idaapi.get_member_by_name(struc, "rtti")
                tinfo = idaapi.tinfo_t()
                idaapi.parse_decl(tinfo, idaapi.cvar.idati, "void* rtti;", idaapi.PT_TYP)
                idaapi.set_member_tinfo(struc, struct_member, 8, tinfo, idaapi.TINFO_DEFINITE)
                for func in vtab_decls[key]:
                    func_type = parse_func(func)
                    print("Func Type: ", func_type)
                    if not isinstance(func_type, list) and len(func_type) > 0:
                        if "~" in func_type:
                            func_type = func_type.replace("~", "DTOR_")
                        func_name = extract_function_name(func_type) 
                        if func_name not in curr_members:
                            curr_members[func_name] = 0
                        else:
                            curr_members[func_name] += 1
                            func_name = f"{func_name}_{curr_members[func_name]}"
                        #Adds semicolon if not previously added
                        if ";" not in func_type:
                            func_type += ";"
                        #Comments below explain this case too
                        if "_0" in func_type:
                            func_type = func_type.replace("_0", "")
                        #Edge case again, although this can be fixed as well as ^^ with typedefs 
                        #typedef <name_of_class> <name_of_class>_1;
                        if "_1" in func_type:
                            func_type = func_type.replace("_1", "")
                        if "::*" in func_type:
                            func_type = func_type.replace("::*", "*")
                        #_vm_map seems to be weird edge case, created a typedef for it
                        #typedef vm_map_t _vm_map;
                        if "_vm_map" in func_type:
                            tinfo = idaapi.tinfo_t()
                            til = idaapi.cvar.idati
                            local_type_details = f"typedef vm_map_t _vm_map;"
                            type_decl = idaapi.parse_decl(tinfo, til, local_type_details, ida_typeinf.PT_TYP)
                            if type_decl:
                                index = idc.set_local_type(-1, local_type_details, ida_typeinf.PT_TYP)
                                if index != -1:
                                    print(f"Successfully added local type: {local_type_details}")
                        print(f"Func Type before processing: {func_type}")
                        #func_type = var_generic_names(func_type)
                        # First, define local types for all the template parameters
                        if "<" in func_type and ">" in func_type:
                            template_type = func_type[:func_type.find(">") + 1]
                            template_type_cleaned = template_type.replace("<", "_").replace(">", "")
                            temp_type = template_type_cleaned.split("_")[1]
                            temp_type_str = f"struct {temp_type};"
                            print(f"Parameter Type: {temp_type_str}")
                            result = idc.set_local_type(-1, temp_type_str, ida_typeinf.PT_TYP)
                            print(f"Result for parameter type: {result}")

        # Then, create the typedef using the previously defined template parameter types
                        if "<" in func_type and ">" in func_type:
                            local_type_details = f"typedef struct {temp_type} *{template_type_cleaned};"
                            print(f"Template type: {local_type_details}")
                            result = idc.set_local_type(-1, local_type_details, ida_typeinf.PT_TYP)
                            print(f"Result for template type: {result}")

                            func_type = func_type.replace(template_type, template_type_cleaned)
                        print(f"Func Type after processing: {func_type}")
                        parameter_list = extract_parameter_types(func_type)
                        print(parameter_list)
                        for param in parameter_list:
                            if param in types_list or param in defined_types or local_type_exists(param) == True:
                                print("Existing Param: ", param)
                                continue
                            else:
                                temp_param = param
                                if "const" in temp_param:
                                    temp_param = temp_param.replace("const", "")
                                if "*" in param:
                                    temp_param = temp_param.replace("*","")
                                local_type_details = f"struct {temp_param};"
                                print("Local Type: ", local_type_details)
                                #type_decl = idaapi.parse_decl(tinfo, til, local_type_details, ida_typeinf.PT_TYP)
                                index = idc.set_local_type(-1, local_type_details, idaapi.PT_TYP)
                                print(f"Local Type: {local_type_details}\nIndex: {index} << if this is 0 you fucked up </3")
                                defined_types.append(temp_param)
                        print(func_type)
                        add_member = idaapi.add_struc_member(struc, func_name, offset, idc.FF_QWORD, None, 8)
                        struct_member = idaapi.get_member_by_name(struc, func_name)
                        tinfo = idaapi.tinfo_t()
                        til = idaapi.cvar.idati
                        idaapi.parse_decl(tinfo, til, func_type, idaapi.PT_TYP)
                        idaapi.set_member_tinfo(struc, struct_member, offset, tinfo, idaapi.TINFO_DEFINITE)
                        prev_type = func_type
                        offset+=8
                    else:
                        print("Type: ", func_type)
                #Adds main struct
                class_obj = class_dict[struct_name] #Get the current class object
                super_class_name = class_obj.getSuperClass() #get super class name
                super_class_obj = class_dict[super_class_name] if super_class_name in list(class_dict.keys()) else "" #given super class name, get the obj for the super class
                idaapi.add_struc_member(class_struc, "__vftable", 0, idc.FF_QWORD, None, 8) #create a struct member for the vtable
                struc_mem = idaapi.get_member_by_name(class_struc, "__vftable") #grab the vtable member variable
                tinfoo = idaapi.tinfo_t() #tinfo variable
                struc_member_name = struct_name+"_vtbl" #this is the
                struc_member_name += "* __vftable;"
                print("Struct name: ",struct_name)
                idaapi.parse_decl(tinfoo, idaapi.cvar.idati, struc_member_name, idaapi.PT_VAR)
                idaapi.set_member_tinfo(class_struc, struc_mem, 0, tinfoo, idaapi.TINFO_DEFINITE)
                print("Here One")
                #struc_mem = idaapi.get_member_by_name(class_struc, "m")
                #struc_member_name = struct_name+"_mbrs m;"
                #tinfoo = idaapi.tinfo_t()
                #idaapi.parse_decl(tinfoo, idaapi.cvar.idati, struc_member_name, idaapi.PT_VAR)
                #idaapi.set_member_tinfo(class_struc, struc_mem, 8, tinfoo, idaapi.TINFO_DEFINITE)
                #mbrs_size = vtab_size[key] #if "<" not in struct_name else vtab_size["`vtable for'"+struct_name.replace("_vtbl","")[0:struct_name.find("<")]] 
                mbrs_size = class_dict[struct_name].getSize() if struct_name in list(class_dict.keys()) else 200
                idaapi.add_struc_member(class_struc, "mbrs", 8, idc.FF_QWORD, None, mbrs_size)
                mbr_struc_member = idaapi.get_member_by_name(class_struc, "mbrs")
                member_name = f"struct {struct_name} mbrs;" if struct_name in IOKitBaseClasses else f"struct {struct_name}_mbrs mbrs;"
                tinfo = idaapi.tinfo_t()
                til = idaapi.cvar.idati
                print(f"Member name: {member_name}") 
                idaapi.parse_decl(tinfo, til, member_name, idaapi.PT_TYP)
                #idaapi.parse_decl(type_info, idaapi.cvar.idati, member_name, idaapi.PT_TYP)
                idaapi.set_member_tinfo(class_struc, mbr_struc_member, 8, tinfo, idaapi.TINFO_DEFINITE)
                print("Member class size", mbrs_size)
                #if struct_name in list(class_dict.keys()) or demangle_name(get_name(class_dict[struct_name].getSuperClass()),idc.get_inf_attr(idc.INF_LONG_DN)) in list(class_dict.keys()): 
                if super_class_obj != "" and super_class_obj != None: 
                    handle_super_class(class_dict, super_class_obj, mbrs_struct, IOKitBaseClasses) 




def lambda_inherits(args, inherits): #fake lambda cause yk XD swag
    if args[1] not in inherits:
        inherits[str(idc.get_strlit_contents(args[1], strtype = strType))] = ""


#x1: OSSymbol className
#x2: parent metaclass address
#x3: class size
def entry():
    existing_classes = [] #holds the classname of each existing object, used for duplicate class checks
    deprecated_class_dict = {} #this is the last one I swear, it holds the class name and class object
    classes = [] #list of IOClass objects
    classes_dict = {} #Dictionary Structure. Key: Class Name. Value: list that holds holds class args recieved from emulation, args[1], and args[2] respectively
    inherits = {} #key: parent class. value: list of all classes that are inherited 
    global unicorn_instance
    global capstone_instance
    #start: the starting address of the first segment in kcache, used for unicorn virtualiziation 
    #end: the ending address of the final segment, adding 0x400 
    start = ida_segment.get_first_seg().start_ea
    end = (ida_segment.get_last_seg().end_ea + 0x400) & ~0x3ff
    unicorn_instance = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    unicorn_instance.mem_map(start, end-start) 
    unicorn_instance.mem_map(end, 0x400) #size of stack is 1024 bytes 
    unicorn_instance.reg_write(arm64_const.UC_ARM64_REG_SP, end+0x400+0x400)
    unicorn_instance.reg_write(arm64_const.UC_ARM64_REG_CPACR_EL1, 0x300000)
    capstone_instance = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    capstone_instance.detail = True
    osmeta = get_osmeta_constructor()
    print(f"[+] Current OSMetaClass::OSMetaClass constructor addr: {hex(osmeta)}")
    refs = idautils.XrefsTo(osmeta)
    print("[+] OSMeta nondemangled name: ", ida_funcs.get_func_name(osmeta))
    for ref in refs:
        if ida_funcs.get_func(ref.frm) != None: 
            args = unicorn_emulate(ref.frm)
            strType = idc.get_str_type(args[0])
            parent = idc.demangle_name(idaapi.get_name(args[1]), idc.get_inf_attr(idc.INF_LONG_DN))
            className = str(idc.get_strlit_contents(args[0], strtype = strType))
            metaclassAddr = hex(args[1])
            classSize = hex(args[2])
            if parent not in inherits and parent != None and className not in existing_classes:
                inherits[parent.split("::")[0]] = {}
                classes.append(IOClass(className, args[1], args[2]))
                existing_classes.append(className)
                classes_dict[className] = [args[1], args[2]]
                deprecated_class_dict[className[1:].replace("`","").replace("'","")] = IOClass(className, parent, args[2])
            elif parent != None and parent.split("::")[0] in inherits.keys():
                inherits[parent.split("::")[0]][className] = {}
            elif metaclassAddr == "0x0":
                deprecated_class_dict[className[1:].replace("`","").replace("'","")] = IOClass(className, parent, args[2])
                inherits[className] = {}
        else:
            pass
    print("\n"*25)
    print("Printing deprecated_class_dict\n")
    print(deprecated_class_dict)
    print(inherits)
    inherits_dict = {}
    for key in inherits.keys():
        print("Key: ", key, "\n\tValue: ", inherits[key], "\n")
        if bool(inherits[key]):
            temp = next(iter(inherits[key])) 
            if key not in inherits_dict.keys():
                inherits_dict[key] = []
                inherits_dict[key].append(temp)
            elif key in inherits_dict.keys():
                inherits_dict[key].append(temp)
        else:
            continue
    print("\n"*20)
    for key in inherits_dict.keys():
        print(key,"\n")
        print("\t", " ".join([i for i in inherits_dict[key]]))
        id = idc.get_struc_id(key)
        struct = idaapi.get_struc(id)
    nested_inheritance_dict = {} #if all works well, this will hold the inheritance of all the classes in the kernel, god speed solider good luck
    print("\n".join([c.name + " " + idc.demangle_name(idaapi.get_name(c.superClass), idc.get_inf_attr(idc.INF_LONG_DN)).split("::")[0] for c in classes])) 
    nested_inheritance = [[c.name, idc.demangle_name(idaapi.get_name(c.superClass), idc.get_inf_attr(idc.INF_LONG_DN)).split("::")[0]] for c in classes] 
    for nested_class in nested_inheritance:
        if nested_class[1] not in nested_inheritance_dict:
            nested_inheritance_dict[nested_class[1]] = {}
            nested_inheritance_dict[nested_class[1]][nested_class[0]] = {}
            nested_inheritance_dict[nested_class[0]] = {}
        else:
            nested_inheritance_dict[nested_class[1]][nested_class[0]] = {}
    print_dict(nested_inheritance_dict)
    print("\n"*4)
    print_dict(fill_inheritance_gaps(create_class_hierarchy(nested_inheritance)))
    hier = fill_inheritance_gaps(create_class_hierarchy(nested_inheritance))
    print("\n"*20)
    curr_offset = 0
    curr_addr = 0
    print("Inherits dict: \n", hier)
    for key in deprecated_class_dict:
        class_name = deprecated_class_dict[key].getName().replace("'","")[1:]
        superclass_name = deprecated_class_dict[key].getSuperClass().split("::")[0] if deprecated_class_dict[key].getSuperClass() != None else ""
        deprecated_class_dict[key].setName(class_name)
        deprecated_class_dict[key].setSuperClass(superclass_name)
        print("Class Name: ", deprecated_class_dict[key].getName(), "\n")
        print("SuperClass: ", deprecated_class_dict[key].getSuperClass(), "\n")
    create_structs(deprecated_class_dict, inherits)
    #print("Deprecated Class Dict:", deprecated_class_dict, "\n")
    #print("Inherits: ", inherits)
entry()

