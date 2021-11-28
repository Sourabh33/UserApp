package com.library.UserApp.payload.response;

public class LoginMessageResponse extends MessageResponse{


    private JwtResponse response;
    private String message;

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

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public void setMessage(String message) {
        this.message = message;
    }
}
