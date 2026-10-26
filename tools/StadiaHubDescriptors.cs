using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
public class StadiaHubDescriptors {
 [StructLayout(LayoutKind.Sequential)] struct IFACE {public uint size;public Guid guid;public uint flags;public IntPtr reserved;}
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr SetupDiGetClassDevs(ref Guid guid,IntPtr enumerator,IntPtr parent,uint flags);
 [DllImport("setupapi.dll",SetLastError=true)] static extern bool SetupDiEnumDeviceInterfaces(IntPtr set,IntPtr device,ref Guid guid,uint index,ref IFACE iface);
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr set,ref IFACE iface,IntPtr detail,uint size,out uint needed,IntPtr info);
 [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle file,uint code,byte[] input,uint inputSize,byte[] output,uint outputSize,out uint returned,IntPtr overlapped);
 static void Check(bool ok,string action){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),action);}
 public static string Run(string hubInstance, uint port){Guid guid=new Guid("f18a0e88-c30c-11d0-8815-00a0c906bed8");IntPtr set=SetupDiGetClassDevs(ref guid,IntPtr.Zero,IntPtr.Zero,0x12);if(set==new IntPtr(-1))throw new Win32Exception();
 try {for(uint index=0;;index++){IFACE iface=new IFACE();iface.size=(uint)Marshal.SizeOf(iface);if(!SetupDiEnumDeviceInterfaces(set,IntPtr.Zero,ref guid,index,ref iface))break;uint needed;SetupDiGetDeviceInterfaceDetail(set,ref iface,IntPtr.Zero,0,out needed,IntPtr.Zero);IntPtr detail=Marshal.AllocHGlobal((int)needed);string path;try{Marshal.WriteInt32(detail,IntPtr.Size==8?8:6);Check(SetupDiGetDeviceInterfaceDetail(set,ref iface,detail,needed,out needed,IntPtr.Zero),"Interface detail");path=Marshal.PtrToStringUni(IntPtr.Add(detail,4));}finally{Marshal.FreeHGlobal(detail);}if(!path.ToLowerInvariant().Contains(hubInstance.Replace((char)92,(char)35).ToLowerInvariant()))continue;
 using(SafeFileHandle file=CreateFile(path,0x40000000,3,IntPtr.Zero,3,0,IntPtr.Zero)){
 Check(!file.IsInvalid,"Open parent hub");string result="";
 foreach(byte type in new byte[]{1,2}){
 byte[] buffer=new byte[4108];Array.Copy(BitConverter.GetBytes(port),0,buffer,0,4);
 buffer[4]=0x80;buffer[5]=6;buffer[7]=type;buffer[10]=0;buffer[11]=16;
 uint read;Check(DeviceIoControl(file,0x220410,buffer,(uint)buffer.Length,buffer,(uint)buffer.Length,out read,IntPtr.Zero),"Read hub descriptor");
 if(read<12)throw new Exception("Short hub response");
 result+=(type==1?"Device":"Configuration")+" descriptor: "+BitConverter.ToString(buffer,12,(int)read-12)+"\n";
 }return result;
 }}throw new Exception("Parent USB hub interface not found");}finally{SetupDiDestroyDeviceInfoList(set);}}
}
