using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
public class StadiaUsbDescriptors {
 [StructLayout(LayoutKind.Sequential)] struct IFACE {public uint size;public Guid guid;public uint flags;public IntPtr reserved;}
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr SetupDiGetClassDevs(ref Guid guid,IntPtr enumerator,IntPtr parent,uint flags);
 [DllImport("setupapi.dll",SetLastError=true)] static extern bool SetupDiEnumDeviceInterfaces(IntPtr set,IntPtr device,ref Guid guid,uint index,ref IFACE iface);
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr set,ref IFACE iface,IntPtr detail,uint size,out uint needed,IntPtr info);
 [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("winusb.dll",SetLastError=true)] static extern bool WinUsb_Initialize(SafeFileHandle file,out IntPtr usb);
 [DllImport("winusb.dll")] static extern bool WinUsb_Free(IntPtr usb);
 [DllImport("winusb.dll",SetLastError=true)] static extern bool WinUsb_GetDescriptor(IntPtr usb,byte type,byte index,ushort language,byte[] buffer,uint length,out uint transferred);
 static void Check(bool ok,string action){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),action);}
 public static string Run(){Guid guid=new Guid("8d3e4437-0f1f-483b-b52e-c7306f0c89c0");IntPtr set=SetupDiGetClassDevs(ref guid,IntPtr.Zero,IntPtr.Zero,0x12);if(set==new IntPtr(-1))throw new Win32Exception();
 try {for(uint index=0;;index++){IFACE iface=new IFACE();iface.size=(uint)Marshal.SizeOf(iface);if(!SetupDiEnumDeviceInterfaces(set,IntPtr.Zero,ref guid,index,ref iface))break;uint needed;SetupDiGetDeviceInterfaceDetail(set,ref iface,IntPtr.Zero,0,out needed,IntPtr.Zero);IntPtr detail=Marshal.AllocHGlobal((int)needed);string path;try{Marshal.WriteInt32(detail,IntPtr.Size==8?8:6);Check(SetupDiGetDeviceInterfaceDetail(set,ref iface,detail,needed,out needed,IntPtr.Zero),"Interface detail");path=Marshal.PtrToStringUni(IntPtr.Add(detail,4));}finally{Marshal.FreeHGlobal(detail);}if(!path.ToLowerInvariant().Contains("vid_18d1&pid_9400&mi_00"))continue;
 using(SafeFileHandle file=CreateFile(path,0xC0000000,3,IntPtr.Zero,3,0x40000000,IntPtr.Zero)){Check(!file.IsInvalid,"Open Stadia MI_00");IntPtr usb;Check(WinUsb_Initialize(file,out usb),"Initialize WinUSB");try{uint read; string result="";byte[] descriptor=new byte[4096];Check(WinUsb_GetDescriptor(usb,1,0,0,descriptor,18,out read),"Device descriptor");result+="Device descriptor: "+BitConverter.ToString(descriptor,0,(int)read)+"\n";
 Check(WinUsb_GetDescriptor(usb,2,0,0,descriptor,4096,out read),"Configuration descriptor");result+="Configuration descriptor ("+read+" bytes): "+BitConverter.ToString(descriptor,0,(int)read)+"\n";return result;
 }finally{WinUsb_Free(usb);}}}throw new Exception("No present Stadia WinUSB interface found");}finally{SetupDiDestroyDeviceInfoList(set);}}
}
