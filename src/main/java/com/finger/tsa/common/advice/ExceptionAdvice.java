package com.finger.tsa.common.advice;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.finger.tsa.common.response.CommonResult;
import com.finger.tsa.common.response.ResponseService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestControllerAdvice
public class ExceptionAdvice {

	private final ResponseService responseService;
	private final MessageSource messageSource; 


	@ExceptionHandler(Exception.class) //모든 Exception 
	@ResponseStatus(code = HttpStatus.INTERNAL_SERVER_ERROR)
	protected CommonResult defaultException(HttpServletRequest request, Exception e) {
		return responseService.getFailResult(Integer.valueOf(getMessage("unKnown.code")), getMessage("unKnown.msg"));
	}

	@ExceptionHandler(FchainException.class)
	protected CommonResult FchainException(HttpServletRequest request, FchainException e) {
		return responseService.getFailResult(e.getCode(), e.getMessage());
	}
	
    //code정보에 해당하는 메시지를 조회.
    private String getMessage(String code) {
        return getMessage(code, null);
    }
    
    //code정보, 추가 argument로 현재 locale에 맞는 메시지를 조회.
    private String getMessage(String code, Object[] args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

}
