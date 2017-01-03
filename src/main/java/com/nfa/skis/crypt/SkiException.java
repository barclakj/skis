package com.nfa.skis.crypt;

/**
 * Created by barclakj on 27/12/2016.
 */
public class SkiException extends InternalSkiException {

    public SkiException() {
        super();
    }

    public SkiException(String msg) {
        super(msg);
    }

    public SkiException(Throwable e) {
        super(e);
    }
}
