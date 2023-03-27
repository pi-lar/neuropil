package utils;

import common.LoadLibrary;
import common.NeuropilObjectManager;
import enums.NpLimits;
import interfaces.Neuropil;
import jnr.ffi.ObjectReferenceManager;
import jnr.ffi.Pointer;
import models.NeuropilNode;
import models.NpMxProperties;
import models.NpToken;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class NeuropilUtils {

    public static NeuropilNode fromContext(Pointer context){
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        Pointer ptr = neuropil.np_get_userdata(context);
        final ObjectReferenceManager referenceManager = NeuropilObjectManager.getInstance().objectReferenceManager;
        NeuropilNode node = (NeuropilNode) referenceManager.get(ptr);
        return node;
    }

    public static NpMxProperties getMxProperties(Pointer context,byte [] subject){
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;

        return neuropil.np_get_mx_properties(context,subject);
    }

    public static boolean executeCallback(Method method, NeuropilNode node, NpToken token){
        try {
            Object obj = method.invoke(null, new Object[] { node, token });
            return Boolean.getBoolean(obj.toString());
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }


}
