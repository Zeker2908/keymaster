package ru.zeker.keymaster.exception.mapper;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.exception.ErrorResponseFactory;
import ru.zeker.keymaster.exception.ServiceOverloadedException;
import ru.zeker.keymaster.exception.TooManyRequestsException;

import java.net.URI;
import java.time.Duration;
import java.util.concurrent.RejectedExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionMapperTest {

    @Test
    void setsRetryAfterHeaderForThrottlingException() {
        UriInfo uriInfo = uriInfo();
        GlobalExceptionMapper mapper = mapperFor(429, uriInfo);

        Response response = mapper.handleKeyMaster(
                new TooManyRequestsException(Duration.ofMillis(4_501)),
                uriInfo
        );

        assertEquals(429, response.getStatus());
        assertEquals("5", response.getHeaderString("Retry-After"));
    }

    @Test
    void setsAtLeastOneSecondRetryAfterForZeroDuration() {
        UriInfo uriInfo = uriInfo();
        GlobalExceptionMapper mapper = mapperFor(429, uriInfo);

        Response response = mapper.handleKeyMaster(
                new TooManyRequestsException(Duration.ZERO),
                uriInfo
        );

        assertEquals("1", response.getHeaderString("Retry-After"));
    }

    @Test
    void roundsSubSecondRetryAfterUpToOneSecond() {
        UriInfo uriInfo = uriInfo();
        GlobalExceptionMapper mapper = mapperFor(429, uriInfo);

        Response response = mapper.handleKeyMaster(
                new TooManyRequestsException(Duration.ofMillis(1)),
                uriInfo
        );

        assertEquals("1", response.getHeaderString("Retry-After"));
    }

    @Test
    void setsDefaultRetryAfterHeaderForOverloadedService() {
        UriInfo uriInfo = uriInfo();
        GlobalExceptionMapper mapper = mapperFor(503, uriInfo);

        Response response = mapper.handleKeyMaster(
                new ServiceOverloadedException(new RejectedExecutionException("full")),
                uriInfo
        );

        assertEquals(503, response.getStatus());
        assertEquals("2", response.getHeaderString("Retry-After"));
    }

    private GlobalExceptionMapper mapperFor(int status, UriInfo uriInfo) {
        ErrorResponseFactory factory = mock(ErrorResponseFactory.class);
        when(factory.create(anyInt(), anyString(), anyString(), anyList(), eq(uriInfo)))
                .thenReturn(Response.status(status).build());
        return new GlobalExceptionMapper(factory);
    }

    private UriInfo uriInfo() {
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getRequestUri()).thenReturn(URI.create("http://localhost/v1/auth/login"));
        return uriInfo;
    }
}
