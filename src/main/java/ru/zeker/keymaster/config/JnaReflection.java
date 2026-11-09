package ru.zeker.keymaster.config;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection(
        targets = {
                com.sun.jna.Pointer.class,
                com.sun.jna.Native.class,
                com.sun.jna.Structure.class,
                com.sun.jna.Library.class,
                com.sun.jna.NativeLong.class
        },
        classNames = "de.mkammerer.argon2.Argon2Library")
public class JnaReflection {
}
