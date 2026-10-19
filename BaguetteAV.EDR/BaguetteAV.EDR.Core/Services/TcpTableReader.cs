using BaguetteAV.EDR.Core.Interop;
using System.Net;
using System.Runtime.InteropServices;

namespace BaguetteAV.EDR.Core.Services;

public sealed record TcpConnection(int ProcessId, string LocalAddress, int LocalPort,
    string RemoteAddress, int RemotePort, string State);

public sealed class TcpTableReader
{
    private const int AfInet = 2;
    private const uint TcpTableOwnerPidAll = 5;
    private const uint ErrorInsufficientBuffer = 122;

    public IReadOnlyList<TcpConnection> Read()
    {
        var result = new List<TcpConnection>(128);
        var size = 0;
        var first = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        if (first != ErrorInsufficientBuffer || size <= 4) return result;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var status = NativeMethods.GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
            if (status != 0) return result;
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();
            var rowPtr = IntPtr.Add(buffer, 4);
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
                var remote = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                var local = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString();
                if (remote == "0.0.0.0") continue;
                result.Add(new TcpConnection(
                    (int)row.owningPid,
                    local,
                    (ushort)IPAddress.NetworkToHostOrder((short)(row.localPort & 0xFFFF)),
                    remote,
                    (ushort)IPAddress.NetworkToHostOrder((short)(row.remotePort & 0xFFFF)),
                    StateText(row.state)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    private static string StateText(uint state) => state switch
    {
        2 => "SYN_SENT",
        5 => "ESTABLISHED",
        8 => "CLOSE_WAIT",
        _ => state.ToString()
    };
}
