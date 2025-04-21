package org.spongycastle.jce.provider;

import java.security.cert.CRLException;

class BCExtCRLException
    extends CRLException
{
    Throwable cause;

    BCExtCRLException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
