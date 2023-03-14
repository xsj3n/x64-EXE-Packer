use goblin::archive::Header;
use memoffset::offset_of;
use windows::{
    core::*, Data::Xml::Dom::*, Win32::Foundation::*, Win32::System::Threading::*,
    Win32::UI::WindowsAndMessaging::*,
};

use std::{arch::asm, io::{Read, Write, Seek, SeekFrom}, u8, mem::size_of, ops::Add, os::windows::prelude::{AsRawHandle, FileExt}, fs::OpenOptions};

use pelite::image::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_FILE_HEADER};

// aligned = ((operand + (alignment - 1)) & ~(alignment - 1))
macro_rules! file_alignment {
    ($x:ident) => {
        ( ($x + (0x200 - 1)) / 0x200 ) * 0x200
    };
}

macro_rules! section_alignment {
    ($x:ident) => {
        ( ($x + (0x1000 - 1)) / 0x1000 ) * 0x1000
    };
}

struct DatHolder {
    dat: Vec<u8>,
}

struct NT64 {
    h: IMAGE_NT_HEADERS64,
    offset_to_nt: usize,
}




impl DatHolder {
    unsafe fn get_dos(&self) -> IMAGE_DOS_HEADER{
    
        let mut dos:  IMAGE_DOS_HEADER = unsafe {std::mem::zeroed()};
        let mut stubsl = self.dat.as_slice();
        // copy 64 bytes stub_ptr => dos_ptr
        unsafe {
            let struct_slice = std::slice::from_raw_parts_mut(&mut dos as *mut IMAGE_DOS_HEADER as *mut u8, 64);
            stubsl.read_exact(struct_slice).unwrap();
        };dos
    }

   unsafe fn get_nt(&self) -> NT64 {
        let mut nt: IMAGE_NT_HEADERS64 = unsafe {std::mem::zeroed()};
        let sz = std::mem::size_of::<IMAGE_NT_HEADERS64>();
        let stubsl = self.dat.as_slice();
        let offset = self.get_dos().e_lfanew as isize;
    
        // src -> ntslice | dst -> struct_slice
        unsafe {
            let mut nt_slice = std::slice::from_raw_parts(stubsl.as_ptr().offset(offset), sz);
            let struct_slice = std::slice::from_raw_parts_mut(&mut nt as *mut IMAGE_NT_HEADERS64 as *mut u8, sz);
            nt_slice.read_exact(struct_slice).unwrap();
            // nt_ptr is useful for latter offset calcs
           let r = NT64 {
            h: nt,
            offset_to_nt: offset as usize,
           }; 
           return r;
        };
        
    } 
    
    unsafe fn get_seh(&self, nt: &NT64, index: i8) -> IMAGE_SECTION_HEADER {
        let mut seh: IMAGE_SECTION_HEADER = unsafe {std::mem::zeroed()};
        let sz = std::mem::size_of::<IMAGE_SECTION_HEADER>();
        let stubsl = self.dat.as_slice();
        
        let offset = offset_of!(IMAGE_NT_HEADERS64, OptionalHeader) + nt.h.FileHeader.SizeOfOptionalHeader as usize + nt.offset_to_nt + (index as usize * sz);
        unsafe {
            let mut seh_slice = std::slice::from_raw_parts(stubsl.as_ptr().offset(offset as isize), sz);
            let struct_slice = std::slice::from_raw_parts_mut(&mut seh as *mut IMAGE_SECTION_HEADER as *mut u8, sz);
            seh_slice.read_exact(struct_slice).unwrap();
        } seh
    }

    unsafe fn increment_number_of_sections(&mut self, nt: &NT64) -> () { 
        // imgbase + nt.offset_to_nt + sizeof(nt.signature) -> IMGE_FILE_HEADER
        const SZ: usize = std::mem::size_of::<IMAGE_FILE_HEADER>();
        let offset = nt.offset_to_nt + std::mem::size_of::<u32>();
        let feh_slice_dst: &mut [u8] = &mut self.dat[offset..offset + SZ];

        let mut updated_feh = IMAGE_FILE_HEADER {
            Machine: nt.h.FileHeader.Machine,
            NumberOfSections: nt.h.FileHeader.NumberOfSections + 1,
            TimeDateStamp: nt.h.FileHeader.TimeDateStamp,
            PointerToSymbolTable: nt.h.FileHeader.PointerToSymbolTable,
            NumberOfSymbols: nt.h.FileHeader.NumberOfSymbols,
            SizeOfOptionalHeader: nt.h.FileHeader.SizeOfOptionalHeader,
            Characteristics: nt.h.FileHeader.Characteristics,
        };
        let mut feh_slice_src = std::slice::from_raw_parts(&mut updated_feh as *mut _ as *mut u8, SZ);
        _ = feh_slice_src.read_exact(feh_slice_dst).unwrap();

    }

}




unsafe fn add_data_to_section_from_file(nt: &NT64, implantfile_src: &str, implant_dst: &str) -> bool  {
    let mut src_data = match std::fs::read(implantfile_src) {
        Ok(f) => f,
        Err(e) => panic!("[-] Error Adding Data to EOF: {}", e),
    };

    let mut fopt = OpenOptions::new(); 
    fopt.read(true).write(true).append(true);
    let mut dst_file = match fopt.open(implant_dst) {
        Ok(f) => f,
        Err(e) => panic!("[-] Error Opening Dst File for Modification: {}", e),
    };
    
    dst_file.seek(SeekFrom::End(0)).unwrap();
    println!("[*] Implanting new information at: {}", dst_file.seek(SeekFrom::Current(0)).unwrap());
    dst_file.write_all(&mut src_data).unwrap(); true

}



unsafe fn append_scn_header(name: &str, image: &mut DatHolder, nt: &NT64, implantize: u32) -> bool {
    let seh_sz = std::mem::size_of::<IMAGE_SECTION_HEADER>();
    let nt_sz = std::mem::size_of::<IMAGE_NT_HEADERS64>();
    let offset_to_newscn = offset_of!(IMAGE_NT_HEADERS64, OptionalHeader) + nt.h.FileHeader.SizeOfOptionalHeader as usize + nt.offset_to_nt + (7 * seh_sz);
    let ptr: *mut u8 = image.dat.as_mut_ptr().offset(offset_to_newscn as isize);
    // mutable slice of target for new section
    let new_scn_slice_dst = std::slice::from_raw_parts_mut(ptr, seh_sz);
    let by = name.as_bytes();
    let nwname: [u8; 8] = [by[0], by[1], by[2], by[3], by[4], by[5], by[6], by[7]];

    // make slice of new struct and copy it to new_scn_slice
    let mut new_scn_struct = IMAGE_SECTION_HEADER {
        Name: nwname,
        VirtualSize: implantize,
        VirtualAddress: 0x00029000,
        SizeOfRawData: file_alignment!(implantize),
        PointerToRawData: 0x00023600,
        PointerToRelocations: 0x0,
        PointerToLinenumbers: 0x0,
        NumberOfLinenumbers: 0x0,
        NumberOfRelocations: 0x0,
        Characteristics: 0x40000040,
    };

    let mut new_scn_slice_src = std::slice::from_raw_parts(&mut new_scn_struct as *mut _ as *mut u8, seh_sz);
    _ = match new_scn_slice_src.read_exact(new_scn_slice_dst) {
       Ok(()) => (),
       Err(e) => panic!("[-] Error Filling New SEH in Image: {}", e),
   }; 

   // cleanse and begin operations to update nt.optionalheader.sizeofimage 
   std::mem::drop(offset_to_newscn);
   std::mem::drop(ptr);
   std::mem::drop(by);
   std::mem::drop(nwname);
   std::mem::drop(new_scn_slice_dst);
   std::mem::drop(new_scn_slice_src);

   let lst_seh = image.get_seh(&nt, nt.h.FileHeader.NumberOfSections as i8);
   let new_sz_of_img = lst_seh.VirtualAddress + lst_seh.VirtualSize;

   let nt_slice_dst = &mut image.dat[nt.offset_to_nt..nt.offset_to_nt + nt_sz];
   let mut new_nt_struct = IMAGE_NT_HEADERS64 {
    Signature: nt.h.Signature,
    FileHeader: nt.h.FileHeader,
    OptionalHeader: nt.h.OptionalHeader,
   };
   new_nt_struct.OptionalHeader.SizeOfImage = section_alignment!(new_sz_of_img);
   let mut nt_slice_src = std::slice::from_raw_parts(&mut new_nt_struct as *mut _ as *mut u8, nt_sz);
   nt_slice_src.read_exact(nt_slice_dst).unwrap();


   true
}






fn main() -> () { 

   

    let scn_name = ".xss\0\0\0\0";

    let mut stubdata = match std::fs::read("..\\dat\\stub.exe") {
        Ok(f) => DatHolder{ dat: f },
        Err(e)  => panic!("[*] Error Reading File: {}", e),
    };

    unsafe {
        let nt = stubdata.get_nt();
        let _b = append_scn_header(scn_name, &mut stubdata, &nt, 0x21C00);
        let seh = stubdata.get_seh(&nt, 7);
        _ = stubdata.increment_number_of_sections(&nt);
        println!("Virtual Size of New Section: {}", seh.VirtualSize);
    }

    let mut out = match std::fs::File::create("output.exe") {
        Ok(f) => f,
        Err(e) => panic!("[*] Error Creating File: {}", e),
    }; _ = out.write_all(&stubdata.dat);
    std::mem::drop(out);
   
    unsafe {
       _ =  add_data_to_section_from_file(&stubdata.get_nt(), "..\\dat\\Project1.exe", "output.exe");
    }
    
   
    std::process::exit(0);
    
}
