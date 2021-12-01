package com.library.UserApp.payload.response;

public class LoginMessageResponse extends MessageResponse{

    private JwtResponse response;

    public LoginMessageResponse(String message, boolean isSuccess, JwtResponse response) {
        super(message, isSuccess);
        this.response = response;
    }

    public JwtResponse getResponse() {
        return response;
    }

    public void setResponse(JwtResponse response) {
        this.response = response;
    }
}
