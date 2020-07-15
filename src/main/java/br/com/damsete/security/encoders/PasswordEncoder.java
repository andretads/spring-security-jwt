package br.com.damsete.security.encoders;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordEncoder {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public PasswordEncoder(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public String encode(String password) {
        return this.bCryptPasswordEncoder.encode(password);
    }
}
