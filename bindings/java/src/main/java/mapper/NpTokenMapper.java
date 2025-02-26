package mapper;

import enums.NpLimits;
import jnr.ffi.Pointer;
import models.NpToken;

import java.nio.charset.Charset;

public class NpTokenMapper {

    public static NpToken convert(Pointer token){
        NpToken npToken = new NpToken(token.getRuntime());

        int actualPosition = 0;
        npToken.uuid.set(token.getString(actualPosition, NpLimits.NP_UUID_BYTES.intValue(),
                Charset.forName("UTF-8")));
        actualPosition += NpLimits.NP_UUID_BYTES.intValue();

        npToken.subject.set(token.getString(actualPosition,
                (actualPosition +255) , Charset.forName("UTF-8") ));
        actualPosition += 255;

        npToken.issuer.set(token.getString(actualPosition,
                (actualPosition + NpLimits.NP_FINGERPRINT_BYTES.intValue()) , Charset.forName("UTF-8") ));
        actualPosition += NpLimits.NP_FINGERPRINT_BYTES.intValue();

        npToken.realm.set(token.getString(actualPosition,
                (actualPosition + NpLimits.NP_FINGERPRINT_BYTES.intValue()) , Charset.forName("UTF-8") ));
        actualPosition += NpLimits.NP_FINGERPRINT_BYTES.intValue();

        npToken.audience.set(token.getString(actualPosition,
                (actualPosition + NpLimits.NP_FINGERPRINT_BYTES.intValue()) , Charset.forName("UTF-8") ));
        actualPosition += NpLimits.NP_FINGERPRINT_BYTES.intValue();

        npToken.issuedAt.set(token.getDouble(actualPosition));
        actualPosition += 64;

        npToken.notBefore.set(token.getDouble(actualPosition));
        actualPosition += 64;

        npToken.expiresAt.set(token.getDouble(actualPosition));
        actualPosition += 64;

        npToken.publicKey.set(token.getString(actualPosition,
                (actualPosition + NpLimits.NP_PUBLIC_KEY_BYTES.intValue()) , Charset.forName("UTF-8") ));
        actualPosition += NpLimits.NP_PUBLIC_KEY_BYTES.intValue();

        npToken.secretKey.set(token.getString(actualPosition,
                (actualPosition + NpLimits.NP_SECRET_KEY_BYTES.intValue()) , Charset.forName("UTF-8") ));
        actualPosition += NpLimits.NP_SECRET_KEY_BYTES.intValue();

        npToken.signature.set(token.getString(actualPosition,
                (actualPosition + NpLimits.NP_SIGNATURE_BYTES.intValue()) , Charset.forName("UTF-8") ));
        actualPosition += NpLimits.NP_SIGNATURE_BYTES.intValue();

        npToken.attributes.set(token.getString(actualPosition,
                (actualPosition + NpLimits.NP_EXTENSION_BYTES.intValue()) , Charset.forName("UTF-8") ));
        actualPosition += NpLimits.NP_SECRET_KEY_BYTES.intValue();

        npToken.attributesSignature.set(token.getString(actualPosition,
                (actualPosition + NpLimits.NP_SIGNATURE_BYTES.intValue()) , Charset.forName("UTF-8") ));

        return npToken;
    }

}
