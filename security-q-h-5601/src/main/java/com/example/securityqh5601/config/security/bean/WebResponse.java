package com.example.securityqh5601.config.security.bean;


//import com.spring4all.constant.CommonResponse;
//import com.spring4all.constant.HttpResponseStatusEnum;
//import lombok.AllArgsConstructor;
//import lombok.Data;
//import lombok.NoArgsConstructor;

import com.example.securityqh5601.config.security.constant.CommonResponse;
import com.example.securityqh5601.config.security.constant.HttpResponseStatusEnum;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

//import lombok.AllArgsConstructor;
//import lombok.Data;
//import lombok.NoArgsConstructor;

/**
 * HTTP 统一响应结果
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class WebResponse {
    /**
     * 响应码
     */
    private String code;

    /**
     * 提示信息
     */
    private String message;

    /**
     * 结果
     */
    private Object result;

    //与这个注解@NoArgsConstructor有关
//    public WebResponse() {
//        super();
//    }

    public WebResponse(HttpResponseStatusEnum httpResponseStatusEnum) {
        this.code = httpResponseStatusEnum.getCode();
        this.message = httpResponseStatusEnum.getMessage();
    }

    public WebResponse(CommonResponse commonResponse) {
        this.code = commonResponse.getCode();
        this.message = commonResponse.getMessage();
    }

    //与这个注解@AllArgsConstructor有关
//    //如果使用lombok则可以不使用这个
//    public WebResponse(String code, String message, Object o) {
//        this.code = code;
//        this.message = message;
//        this.result = o;
//
//    }

    /**
     * 成功响应
     */
    public static WebResponse success() {
        return new WebResponse(HttpResponseStatusEnum.SUCCESS.getCode(),
                HttpResponseStatusEnum.SUCCESS.getMessage(), null);
    }

    /**
     * 成功响应
     */
    public static WebResponse success(Object result) {
        return new WebResponse(HttpResponseStatusEnum.SUCCESS.getCode(),
                HttpResponseStatusEnum.SUCCESS.getMessage(), result);
    }

    /**
     * 禁止操作
     */
    public static WebResponse forbidden() {
        return new WebResponse(HttpResponseStatusEnum.FORBIDDEN_OPERATION.getCode(),
                HttpResponseStatusEnum.FORBIDDEN_OPERATION.getMessage()+"拒绝访问处理器（登录状态下，无权限会触发）", null);
    }

    ////与这个注解@Data有关

//    public String getCode() {
//        return code;
//    }
//
//    public void setCode(String code) {
//        this.code = code;
//    }
//
//    public String getMessage() {
//        return message;
//    }
//
//    public void setMessage(String message) {
//        this.message = message;
//    }
//
//    public Object getResult() {
//        return result;
//    }
//
//    public void setResult(Object result) {
//        this.result = result;
//    }
}
