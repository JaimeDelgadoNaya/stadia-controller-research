param([string]$OutFile)
$ErrorActionPreference = 'Stop'
# Metadata only: no ReadFile/WriteFile, feature requests, or output reports.
if (-not ('StadiaHidMetadata' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public class StadiaHidMetadata {
 [StructLayout(LayoutKind.Sequential)] struct IFACE {public uint size;public Guid guid;public uint flags;public IntPtr reserved;}
 [StructLayout(LayoutKind.Sequential)] struct ATTR {public int size;public ushort vendor,product,version;}
 [DllImport("hid.dll")] static extern void HidD_GetHidGuid(out Guid guid);
 [DllImport("hid.dll")] static extern bool HidD_GetAttributes(SafeFileHandle file,ref ATTR attributes);
 [DllImport("hid.dll")] static extern bool HidD_GetPreparsedData(SafeFileHandle file,out IntPtr data);
 [DllImport("hid.dll")] static extern bool HidD_FreePreparsedData(IntPtr data);
 [DllImport("hid.dll")] static extern int HidP_GetCaps(IntPtr data,[Out] byte[] caps);
 [DllImport("hid.dll")] static extern int HidP_GetValueCaps(short type,[Out] byte[] caps,ref ushort count,IntPtr data);
 [DllImport("hid.dll")] static extern int HidP_GetButtonCaps(short type,[Out] byte[] caps,ref ushort count,IntPtr data);
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr SetupDiGetClassDevs(ref Guid guid,IntPtr enumerator,IntPtr parent,uint flags);
 [DllImport("setupapi.dll",SetLastError=true)] static extern bool SetupDiEnumDeviceInterfaces(IntPtr set,IntPtr device,ref Guid guid,uint index,ref IFACE iface);
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr set,ref IFACE iface,IntPtr detail,uint size,out uint needed,IntPtr info);
 [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 static ushort U(byte[] b,int at){return BitConverter.ToUInt16(b,at);}
 static void Check(bool ok,string action){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),action);}
 static void Status(int status,string action){if(status!=0x00110000)throw new Exception(action+" HID status 0x"+status.ToString("X8"));}
 static Dictionary<string,object> Caps(byte[] b,int at,bool values){
  bool range=b[at+12]!=0;
  var result=new Dictionary<string,object>{{"usage_page",U(b,at)},{"report_id",b[at+2]},{"link_collection",U(b,at+6)},{"is_range",range},{"usage_min",U(b,at+56)},{"usage_max",range?U(b,at+58):U(b,at+56)}};
  if(values){result["bit_size"]=U(b,at+18);result["report_count"]=U(b,at+20);result["logical_min"]=BitConverter.ToInt32(b,at+40);result["logical_max"]=BitConverter.ToInt32(b,at+44);result["absolute"]=b[at+15]!=0;}
  return result;
 }
 public static List<Dictionary<string,object>> Run(){
  Guid guid;HidD_GetHidGuid(out guid);IntPtr set=SetupDiGetClassDevs(ref guid,IntPtr.Zero,IntPtr.Zero,0x12);
  if(set==new IntPtr(-1))throw new Win32Exception();var result=new List<Dictionary<string,object>>();
  try{for(uint index=0;;index++){
   IFACE iface=new IFACE();iface.size=(uint)Marshal.SizeOf(iface);
   if(!SetupDiEnumDeviceInterfaces(set,IntPtr.Zero,ref guid,index,ref iface)){int error=Marshal.GetLastWin32Error();if(error==259)break;throw new Win32Exception(error,"Enumerate HID interfaces");}
   uint needed;SetupDiGetDeviceInterfaceDetail(set,ref iface,IntPtr.Zero,0,out needed,IntPtr.Zero);
   IntPtr detail=Marshal.AllocHGlobal(checked((int)needed));string path;
   try{Marshal.WriteInt32(detail,IntPtr.Size==8?8:6);Check(SetupDiGetDeviceInterfaceDetail(set,ref iface,detail,needed,out needed,IntPtr.Zero),"HID interface detail");path=Marshal.PtrToStringUni(IntPtr.Add(detail,4));}finally{Marshal.FreeHGlobal(detail);}
   if(path==null || !path.ToLowerInvariant().Contains("vid_18d1&pid_9400"))continue;
   using(SafeFileHandle file=CreateFile(path,0,3,IntPtr.Zero,3,0,IntPtr.Zero)){
    Check(!file.IsInvalid,"Open Stadia HID metadata");ATTR a=new ATTR();a.size=Marshal.SizeOf(a);Check(HidD_GetAttributes(file,ref a),"HID attributes");
    if(a.vendor!=0x18d1 || a.product!=0x9400)continue;IntPtr prep;Check(HidD_GetPreparsedData(file,out prep),"HID preparsed data");
    try{byte[] caps=new byte[64];Status(HidP_GetCaps(prep,caps),"HID capabilities");
     var collection=new Dictionary<string,object>{{"vendor_id","18D1"},{"product_id","9400"},{"device_version",a.version},{"usage_page",U(caps,2)},{"usage",U(caps,0)},{"input_report_bytes",U(caps,4)},{"output_report_bytes",U(caps,6)},{"feature_report_bytes",U(caps,8)}};
     var reports=new List<Dictionary<string,object>>();
     for(short type=0;type<3;type++){
      int baseAt=46+type*6;ushort buttons=U(caps,baseAt),values=U(caps,baseAt+2);
      var buttonList=new List<Dictionary<string,object>>();var valueList=new List<Dictionary<string,object>>();
      if(buttons>0){byte[] buffer=new byte[buttons*72];ushort count=buttons;Status(HidP_GetButtonCaps(type,buffer,ref count,prep),"Button capabilities");for(int n=0;n<count;n++)buttonList.Add(Caps(buffer,n*72,false));}
      if(values>0){byte[] buffer=new byte[values*72];ushort count=values;Status(HidP_GetValueCaps(type,buffer,ref count,prep),"Value capabilities");for(int n=0;n<count;n++)valueList.Add(Caps(buffer,n*72,true));}
      reports.Add(new Dictionary<string,object>{{"type",new string[]{"input","output","feature"}[type]},{"buttons",buttonList},{"values",valueList}});
     }
     collection["reports"]=reports;result.Add(collection);
    }finally{HidD_FreePreparsedData(prep);}
   }
  }}finally{SetupDiDestroyDeviceInfoList(set);}return result;
 }
}
'@
}
$collections = @([StadiaHidMetadata]::Run())
$report = [ordered]@{
    schema_version = 1
    captured_at = [DateTimeOffset]::UtcNow.ToString('o')
    method = 'Windows HID preparsed capabilities; CreateFile desiredAccess=0'
    collection_count = $collections.Count
    collections = $collections
    limits = @(
        'Parsed capabilities, not the raw HID report descriptor or captured report bytes.'
        'No input samples, output reports, feature transfers, mode changes or firmware writes.'
        'A declared output report does not prove its firmware effect or rumble behavior.'
        'No device paths, serial numbers or instance identifiers are included.'
    )
}
$json = $report | ConvertTo-Json -Depth 12
if ($OutFile) { [IO.File]::WriteAllText($OutFile, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false)) }
$json
