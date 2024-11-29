package models;

import common.LoadLibrary;
import common.NeuropilObjectManager;
import enums.NpLimits;
import interfaces.Neuropil;
import jnr.ffi.ObjectReferenceManager;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;
import jnr.ffi.Struct;

import java.nio.charset.StandardCharsets;

public class NpId {
    public byte[] id ;
    public String hex;

    public NpId(byte[] id){
        this.id = id;
        this.updateHex();
    }
    public void updateHex(){
        this.updateHex(65);
    }
    public void updateHex(int size){
        byte[] s = new byte[size];
        for(int i = 0; i < s.length; i++){
            s[i] = '\0';
        }
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        neuropil.np_id_str_java(s, this.id);
        this.hex = new String(s, StandardCharsets.UTF_8).trim();

    }

    public String toString(){
        return this.hex;
    }
}
