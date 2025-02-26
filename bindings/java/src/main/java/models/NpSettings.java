package models;

import jnr.ffi.Runtime;
import jnr.ffi.Struct;

public class NpSettings extends Struct {

    public Struct.SignedLong nThreads = new SignedLong();
    public Struct.String logFile = new Struct.AsciiString(256);
    public Struct.SignedLong logLevel = new SignedLong();
    public Struct.Signed32 leafsetSize = new Signed32();
    public Struct.Signed32 jobqueueSize = new Signed32();
    public Struct.Signed32 maxMsgPerSec = new Signed32();
    public NpSettings(Runtime runtime) {
        super(runtime);
    }

    public void NpSettings(long nThreads, java.lang.String logFile, long logLevel,
                           int leafsetSize, int jobqueueSize, int maxMsgPerSec ){
        this.nThreads.set(nThreads);
        this.logFile.set(logFile);
        this.logLevel.set(logLevel);
        this.leafsetSize.set(leafsetSize);
        this.jobqueueSize.set(jobqueueSize);
        this.maxMsgPerSec.set(maxMsgPerSec);
    }
}
