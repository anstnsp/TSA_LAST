package com.finger.tsa.common.response;

import lombok.Getter;

import lombok.Setter;

@Getter 
@Setter
public class SingleResult<T> extends CommonResult {
	
	private T data;
	
}
