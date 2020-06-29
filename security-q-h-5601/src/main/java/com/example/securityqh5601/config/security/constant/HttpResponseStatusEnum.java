package com.example.securityqh5601.config.security.constant;


import lombok.AllArgsConstructor;

//
@AllArgsConstructor
public enum HttpResponseStatusEnum implements CommonResponse {
//     成功请求
    SUCCESS("0", "success"),
    // 权限不足
    FORBIDDEN_OPERATION("2","forbidden");



    private String code;
    private String message;
//    HttpResponseStatusEnum(String code,String message){
//        this.code = code;
//        this.message = message;
//    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public Object getResult() {
        return null;
    }
}
