//package com.finger.tsa.tsa.service;
//
//import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
//
//import java.io.IOException;
//import java.security.NoSuchAlgorithmException;
//import java.security.cert.CertificateException;
//import java.security.spec.InvalidKeySpecException;
//import java.util.concurrent.TimeoutException;
//
//import org.bouncycastle.operator.OperatorCreationException;
//import org.bouncycastle.tsp.TSPException;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
//import org.springframework.test.web.client.MockRestServiceServer;
//
//import com.finger.tsa.common.advice.FchainException;
//import com.finger.tsa.tsa.dto.TSADto;
//
//@RestClientTest(value = TSAService.class)
//public class TSAServiceTest {
//
//    @Autowired
//    private MockRestServiceServer mockServer;
//    
//    @Autowired
//    private TSAService tsaService; 
//    
//    private String url = "http://localhost:4444/v1/api/gettoken";
//    
//    @Test
//    @DisplayName("시점확인 - 등록")
//    public void getFileIncludedToken() throws NoSuchAlgorithmException, IllegalArgumentException, OperatorCreationException, InvalidKeySpecException, NullPointerException, CertificateException, TSPException, IOException, TimeoutException, InterruptedException, FchainException {
//    	
//    	//given
//    	TSADto dto = TSADto.builder().strFromFile("asdfasfd").build();
//    	
//    	String expectedResult = "{\"resultCode\":\"1\"}";
//    	//when
//    	mockServer.expect(requestTo(url))
//    				.andRespond(responseCreator);
//    	tsaService.getFileIncludedToken(dto);
//    	//then
//    }
//    
//}
