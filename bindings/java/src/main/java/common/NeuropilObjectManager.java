package common;

import interfaces.Neuropil;
import jnr.ffi.ObjectReferenceManager;
import jnr.ffi.Runtime;

public class NeuropilObjectManager {

    private static NeuropilObjectManager neuropilObjectManagerInstance = null;

    public ObjectReferenceManager objectReferenceManager;

    private NeuropilObjectManager(){
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        objectReferenceManager = Runtime.getRuntime(neuropil).newObjectReferenceManager();
    }

    public static NeuropilObjectManager getInstance(){
        if (neuropilObjectManagerInstance == null)
            neuropilObjectManagerInstance = new NeuropilObjectManager();

        return neuropilObjectManagerInstance;
    }
}
