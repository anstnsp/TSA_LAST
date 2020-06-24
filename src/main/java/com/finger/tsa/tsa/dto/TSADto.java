package com.finger.tsa.tsa.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
@Builder
@Getter
@Setter
public class TSADto {
	private String strFromFile; 
	private String pdfHash; 		//원본pdf해쉬 
	private String pdfTokenHash; 	//토큰이삽입된 pdf해쉬
	private String tst; 			//타임스탬프 토큰 
	private String issuerDate; 		//토큰만들때 시점
	private String docuSeq; 		//문서일련번호
	private byte[] tstRequest;
	
	
}
