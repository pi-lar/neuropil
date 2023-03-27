package common;

import interfaces.Neuropil;
import jnr.ffi.LibraryLoader;

public class LoadLibrary {

    private static LoadLibrary loadLibraryInstance = null;

    public Neuropil neuropil;

    private LoadLibrary(){
        neuropil = LibraryLoader.create(Neuropil.class).load("neuropil");
    }

    public static LoadLibrary getInstance(){
        if (loadLibraryInstance == null)
            loadLibraryInstance = new LoadLibrary();

        return loadLibraryInstance;
    }
}
