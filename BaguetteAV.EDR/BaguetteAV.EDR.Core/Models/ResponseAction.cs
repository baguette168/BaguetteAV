namespace BaguetteAV.EDR.Core.Models;

[Flags]
public enum ResponseAction
{
    Inherit = 0,
    Alert = 1,
    TerminateProcess = 2,
    QuarantineFile = 4,
    BlockDestination = 8,
    Contain = TerminateProcess | QuarantineFile | BlockDestination
}
