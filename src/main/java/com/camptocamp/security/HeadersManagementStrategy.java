package com.camptocamp.security;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.message.BasicHeader;

/**
 * A strategy for copying headers from the request to the proxied request and
 * the same for the response headers
 * 
 * @author jeichar
 */
public class HeadersManagementStrategy {
    protected static final Log logger = LogFactory.getLog(Proxy.class.getPackage().getName());
    /**
     * If true (default is false) AcceptEncoding headers are removed from request headers
     */
    private boolean noAcceptEncoding = false;
    private List<HeaderProvider> headerProviders = Collections.emptyList(); 
    private List<HeaderFilter> filters = Collections.emptyList();
    /**
     * Copies the request headers from the original request to the proxy request.  It may modify the
     * headers slightly
     */
    @SuppressWarnings("unchecked")
    public void configureRequestHeaders(HttpServletRequest originalRequest, HttpRequestBase proxyRequest) {
        Enumeration<String> headerNames = originalRequest.getHeaderNames();
        String headerName = null;

        StringBuilder headersLog = new StringBuilder("Request Headers:\n");
        headersLog
                .append("==========================================================\n");
        while (headerNames.hasMoreElements()) {
            headerName = headerNames.nextElement();
            if (headerName.compareToIgnoreCase("content-length") == 0) {
                continue;
            }
            if (filter(originalRequest, headerName, proxyRequest)) {
                continue;
            }
            if(noAcceptEncoding && headerName.equalsIgnoreCase("Accept-Encoding")) {
                continue;
            }
            if(headerName.equalsIgnoreCase("host")){
                continue;
            }
            
            String value = originalRequest.getHeader(headerName);
            proxyRequest.addHeader(new BasicHeader(headerName, value));
            headersLog.append("\t" + headerName);
            headersLog.append("=");
            headersLog.append(value);
            headersLog.append("\n");
        }

        for(HeaderProvider provider : headerProviders) {
            for (Header header : provider.getCustomRequestHeaders()) {
                proxyRequest.addHeader(header);
                headersLog.append("\t" + header.getName());
                headersLog.append("=");
                headersLog.append(header.getValue());
                headersLog.append("\n");
            }
        }

        headersLog
                .append("==========================================================");

        logger.trace(headersLog.toString());
    }

    private boolean filter(HttpServletRequest originalRequest, String headerName, HttpRequestBase proxyRequest) {
        for (HeaderFilter filter : filters) {
            if(filter.filter(headerName, originalRequest, proxyRequest)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Copy headers from the proxy response to the final response
     */
    public void copyResponseHeaders(String originalRequest, HttpResponse proxyResponse, HttpServletResponse finalResponse) {
        StringBuilder headersLog = new StringBuilder("Response Headers:\n");
        headersLog
                .append("==========================================================\n");

        // Set Response headers
        for (Header header : proxyResponse.getAllHeaders()) {
            headersLog.append("\t");
            if (header.getName().equalsIgnoreCase("Transfer-Encoding") && header.getValue().equalsIgnoreCase("chunked")){
                headersLog.append("-- IGNORING -- ");
            } else if(header.getName().equalsIgnoreCase("Set-Cookie")) {
                String[] parts = header.getValue().split("(?i)Path=",2);
                String newVal;
                if(parts.length == 1){
                    newVal = header.getValue();
                } else {
                    newVal = parts[0] + "Path= /" + originalRequest.substring("/sec/".length()).split("/")[0];                    
                }
                finalResponse.addHeader(header.getName(), newVal);
            } else {
                finalResponse.addHeader(header.getName(), header.getValue());
            }
            headersLog.append(header.getName());
            headersLog.append("=");
            headersLog.append(header.getValue());
            headersLog.append("\n");
        }
        
        for(HeaderProvider provider : headerProviders) {
            for (Header header : provider.getCustomResponseHeaders()) {
                finalResponse.addHeader(header.getName(), header.getValue());
                headersLog.append("\t" + header.getName());
                headersLog.append("=");
                headersLog.append(header.getValue());
                headersLog.append("\n");
            }
        }

        
        headersLog
                .append("==========================================================\n");

        logger.trace(headersLog.toString());
    }
    
    public void setNoAcceptEncoding(boolean noAcceptEncoding) {
        this.noAcceptEncoding = noAcceptEncoding;
    }
    
    public void setHeaderProviders(List<HeaderProvider> headerProviders) {
        this.headerProviders = headerProviders;
    }
    
    public void setFilters(List<HeaderFilter> filters) {
        this.filters = filters;
    }
}
