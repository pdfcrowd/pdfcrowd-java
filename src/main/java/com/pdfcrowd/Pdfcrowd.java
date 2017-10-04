// Copyright (C) 2009-2016 pdfcrowd.com
// 
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package com.pdfcrowd;

import java.util.*;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;

public final class Pdfcrowd {
    private static final String HOST = System.getenv("PDFCROWD_HOST") != null
        ? System.getenv("PDFCROWD_HOST")
        : "api.pdfcrowd.com";
    private static final String MULTIPART_BOUNDARY = "----------ThIs_Is_tHe_bOUnDary_$";
    public static final String CLIENT_VERSION = "4.0";

    public static final class Error extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public int statusCode = 0;

        public Error() {}
        public Error(Throwable throwable) { super(throwable); }
        public Error(String msg) { super(msg); }
        public Error(String msg, int code) {
            super(msg);
            statusCode = code;
        }

        public String toString() {
            if (statusCode == 0) {
                return getMessage();
            }

            StringBuffer message = new StringBuffer(Integer.toString(statusCode));
            message.append(" - ").append(getMessage());
            return message.toString();
        }

        public String getMessage() {
            return super.getMessage();
        }

        public int getCode() {
            return statusCode;
        }
    }

    private static final class ConnectionHelper {
        private String userName;
        private String apiKey;
        private int port;
        private boolean useHttp;
        private String userAgent;
        private String debugLogUrl;
        private int credits;
        private int consumedCredits;
        private String jobId;
        private int pageCount;
        private int outputSize;

        private String proxyHost;
        private int proxyPort;
        private String proxyUserName;
        private String proxyPassword;    

        ConnectionHelper(String userName, String apiKey) {
            this.userName = userName;
            this.apiKey = apiKey;

            resetResponseData();
            setProxy(null, 0, null, null);
            setUseHttp(false);
            setUserAgent("pdfcrowd_java_client/4.0 (http://pdfcrowd.com)");
        }

        private void resetResponseData() {
            this.debugLogUrl = null;
            this.credits = 999999;
            this.consumedCredits = 0;
            this.jobId = "";
            this.pageCount = 0;
            this.outputSize = 0;
        }

        private static void copyStream(InputStream in, OutputStream out) throws IOException {
            byte[] buffer = new byte[8192];
            while (true) {
                int bytesRead = in.read(buffer, 0, 8192);
                if (bytesRead == -1) break;
                out.write(buffer, 0, bytesRead);
            }
        }

        private static String join(AbstractCollection<String> col, String delimiter) {
            if (col.isEmpty()) return "";
            Iterator<String> iter = col.iterator();
            StringBuffer buffer = new StringBuffer(iter.next());
            while(iter.hasNext()) buffer.append(delimiter).append(iter.next());
            return buffer.toString();
        }

        private static HashMap<String, String> prepareFields(HashMap<String, String> fields) {
            HashMap<String, String> result = new HashMap<String, String>();
            for(Map.Entry<String, String> entry: fields.entrySet()) {
                String value = entry.getValue();
                if (value != null && !value.isEmpty()) {
                    result.put(entry.getKey(), value);
                }
            }
            return result;
        }

        byte[] post(HashMap<String, String> fields, HashMap<String, String> files, HashMap<String, byte[]> rawData, OutputStream outStream) {
            return files.isEmpty() && rawData.isEmpty() ?
                postUrlEncoded(fields, outStream) :
                postMultipart(fields, files, rawData, outStream);
        }

        private byte[] postUrlEncoded(HashMap<String, String> fields, OutputStream outStream) {
            byte[] body = encodePostData(prepareFields(fields));
            String contentType = "application/x-www-form-urlencoded";
            return doPost(body, contentType, outStream);
        }

        private byte[] postMultipart(HashMap<String, String> fields, HashMap<String, String> files, HashMap<String, byte[]> rawData, OutputStream outStream) {
            ByteArrayOutputStream body = encodeMultipartPostData(prepareFields(fields), files, rawData);
            String contentType = "multipart/form-data; boundary=" + MULTIPART_BOUNDARY;
            return doPost(body, contentType, outStream);
        }

        private static byte[] encodePostData(HashMap<String, String> fields) {
            Vector<String> body = new Vector<String>();
            try {
                for(Map.Entry<String, String> entry: fields.entrySet()) {
                    body.add(URLEncoder.encode(entry.getKey(), "UTF-8") + "=" +
                             URLEncoder.encode(entry.getValue(), "UTF-8"));
                }
                return join(body, "&").getBytes("UTF-8");
            }
            catch(UnsupportedEncodingException e) {
                throw new Error(e);
            }
        }

        private static void beginFileField(String name, String fileName, Vector<String> body) {
            body.add("--" + MULTIPART_BOUNDARY);
            body.add(String.format("Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"",
                                   name, fileName));
            body.add("Content-Type: application/octet-stream");
            body.add("");
            body.add("");
        }

        private static ByteArrayOutputStream encodeMultipartPostData(HashMap<String, String> fields, HashMap<String, String> files, HashMap<String, byte[]> rawData) {
            try {
                Vector<String> body = new Vector<String>();
                ByteArrayOutputStream retval = new ByteArrayOutputStream();
                for(Map.Entry<String, String> entry: fields.entrySet()) {
                    body.add("--" + MULTIPART_BOUNDARY);
                    body.add(String.format("Content-Disposition: form-data; name=\"%s\"", entry.getKey()));
                    body.add("");
                    body.add(entry.getValue());
                }
                for(Map.Entry<String, String> entry: files.entrySet()) {
                    beginFileField(entry.getKey(), entry.getValue(), body);
                    retval.write(join(body, "\r\n").getBytes("UTF-8"));
                    body.clear();

                    // read file
                    copyStream(new FileInputStream(entry.getValue()), retval);

                    retval.write("\r\n".getBytes("UTF-8"));
                }

                for(Map.Entry<String, byte[]> entry: rawData.entrySet()) {
                    beginFileField(entry.getKey(), entry.getKey(), body);
                    retval.write(join(body, "\r\n").getBytes("UTF-8"));
                    body.clear();

                    // write binary data
                    retval.write(entry.getValue());

                    retval.write("\r\n".getBytes("UTF-8"));
                }

                body.add("--" + MULTIPART_BOUNDARY);
                body.add("");
                retval.write(join(body, "\r\n").getBytes("UTF-8"));

                return retval;
            }
            catch(UnsupportedEncodingException e) {
                throw new Error(e);
            }
            catch(IOException e) {
                throw new Error(e);
            }
        }

        private final static HostnameVerifier HOSTNAME_VERIFIER = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return hostname.equals("api.pdfcrowd.com") || !HOST.equals("api.pdfcrowd.com");
                }
            };
    
        private HttpURLConnection getConnection(String contentType) throws IOException {
            try {
                URL url = new URL(String.format("http%s://%s:%d%s",
                                                useHttp ? "": "s",
                                                HOST, port, "/convert/"));
                HttpURLConnection conn = null;

                if (proxyHost != null) {
                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
                    conn = (HttpURLConnection) url.openConnection(proxy);
                
                    if (proxyUserName != null) {
                        Authenticator authenticator = new Authenticator() {
                                public PasswordAuthentication getPasswordAuthentication() {
                                    return (new PasswordAuthentication(proxyUserName,
                                                                       proxyPassword.toCharArray()));
                                }
                            };
                        Authenticator.setDefault(authenticator);
                    }
                } else {
                    conn = (HttpURLConnection) url.openConnection();

                    if (!useHttp) {
                        // BUG: sun-java6-bin: missing cacerts the trustAnchors parameter must be non-empty
                        // http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=564903
                        HttpsURLConnection ssl_conn = (HttpsURLConnection)conn;
                        ssl_conn.setHostnameVerifier(HOSTNAME_VERIFIER);
                    }
                }
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", contentType);
                conn.setRequestProperty("User-Agent", userAgent);

                String auth = userName + ':' + apiKey;
                Base64.Encoder encoder = Base64.getEncoder();
                String authEncoded = new String(encoder.encode(auth.getBytes()));
                conn.setRequestProperty("Authorization", "Basic " + authEncoded);
            
                return conn;
            }
            catch(MalformedURLException e) {
                throw new Error(e);
            }
        }

        private static int getIntHeader(HttpURLConnection conn, String name, int defaultValue) {
            String value = conn.getHeaderField(name);
            return value == null ? defaultValue : Integer.parseInt(value);
        }

        private static String getStringHeader(HttpURLConnection conn, String name, String defaultValue) {
            String value = conn.getHeaderField(name);
            return value == null ? defaultValue : value;
        }

        private byte[] doPost(Object body, String contentType, OutputStream outStream) {
            if (!useHttp && proxyHost != null)
                throw new Error("HTTPS over a proxy is not supported.");

            resetResponseData();

            try {
                HttpURLConnection conn = getConnection(contentType);
                OutputStream wr = conn.getOutputStream();
                if (body instanceof byte[]) {
                    wr.write((byte[]) body);
                }
                else {
                    ((ByteArrayOutputStream) body).writeTo(wr);
                }
                wr.flush();
                wr.close();

                debugLogUrl = getStringHeader(conn, "X-Pdfcrowd-Debug-Log", "");
                credits = getIntHeader(conn, "X-Pdfcrowd-Remaining-Credits", 999999);
                consumedCredits = getIntHeader(conn, "X-Pdfcrowd-Consumed-Credits", 0);
                jobId = getStringHeader(conn, "X-Pdfcrowd-Job-Id", "");
                pageCount = getIntHeader(conn, "X-Pdfcrowd-Pages", 0);
                outputSize = getIntHeader(conn, "X-Pdfcrowd-Output-Size", 0);

                if (conn.getResponseCode() > 299) {
                    String errMsg;
                    if (conn.getErrorStream() != null) {
                        ByteArrayOutputStream errOut = new ByteArrayOutputStream();
                        copyStream(conn.getErrorStream(), errOut);
                        errMsg = errOut.toString();
                    }
                    else {
                        errMsg = conn.getResponseMessage();
                    }
                    throw new Error(errMsg, conn.getResponseCode());
                }

                InputStream inStream = conn.getInputStream();

                if (outStream != null) {
                    copyStream(inStream, outStream);
                    inStream.close();
                    return null;
                }

                byte[] buffer = new byte[16384];
                int bytesRead;
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                while ((bytesRead = inStream.read(buffer)) != -1) {
                    output.write(buffer, 0, bytesRead);
                }
                inStream.close();
                return output.toByteArray();
            }
            catch(IOException e) {
                throw new Error(e);
            }
        }

        void setUseHttp(boolean useHttp) {
            this.useHttp = useHttp;
            this.port = useHttp ? 80 : 443;
        }

        void setUserAgent(String userAgent) {
            this.userAgent = userAgent;
        }
        
        void setProxy(String host, int port, String userName, String password) {
            proxyHost = host;
            proxyPort = port;
            proxyUserName = userName;
            proxyPassword = password;
        }

        String getDebugLogUrl() {
            return debugLogUrl;
        }

        int getRemainingCreditCount() {
            return credits;
        }

        int getConsumedCreditCount() {
            return consumedCredits;
        }

        String getJobId() {
            return jobId;
        }

        int getPageCount() {
            return pageCount;
        }

        int getOutputSize() {
            return outputSize;
        }
    }

    static String createInvalidValueMessage(Object value, String field, String converter, String hint, String id) {
        String message = String.format("Invalid value '%s' for a field '%s'.", value, field);
        if(hint != null)
            {
                message += " " + hint;
            }
        return message + " " + String.format("Details: https://www.pdfcrowd.com/doc/api/%s/java/#%s", converter, id);
    }

// generated code

    /**
    * Conversion from HTML to PDF.
    */
    public static final class HtmlToPdfClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;
        
        /**
        * Constructor for the Pdfcrowd API client.
        * 
        * @param userName Your username at Pdfcrowd.
        * @param apiKey Your API key.
        */
        public HtmlToPdfClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "html");
            fields.put("output_format", "pdf");
        }

        /**
        * Convert a web page.
        * 
        * @param url The address of the web page to convert. The supported protocols are http:// and https://.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "url", "html-to-pdf", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a web page and write the result to an output stream.
        * 
        * @param url The address of the web page to convert. The supported protocols are http:// and https://.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "url", "html-to-pdf", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a web page and write the result to a local file.
        * 
        * @param url The address of the web page to convert. The supported protocols are http:// and https://.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "html-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertUrlToStream(url, outputFile);
            outputFile.close();
        }

        /**
        * Convert a local file.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip).<br> If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "html-to-pdf", "The file name must have a valid extension.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a local file and write the result to an output stream.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip).<br> If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "html-to-pdf", "The file name must have a valid extension.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a local file and write the result to a local file.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip).<br> If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "html-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertFileToStream(file, outputFile);
            outputFile.close();
        }

        /**
        * Convert a string.
        * 
        * @param text The string content to convert. The string must not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertString(String text) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "text", "html-to-pdf", "The string must not be empty.", "convert_string"), 470);
            
            fields.put("text", text);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a string and write the output to an output stream.
        * 
        * @param text The string content to convert. The string must not be empty.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertStringToStream(String text, OutputStream outStream) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470);
            
            fields.put("text", text);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a string and write the output to a file.
        * 
        * @param text The string content to convert. The string must not be empty.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertStringToFile(String text, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "html-to-pdf", "The string must not be empty.", "convert_string_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertStringToStream(text, outputFile);
            outputFile.close();
        }

        /**
        * Set the output page size.
        * 
        * @param pageSize Allowed values are A2, A3, A4, A5, A6, Letter.
        */
        public void setPageSize(String pageSize) {
            if (!pageSize.matches("(?i)^(A2|A3|A4|A5|A6|Letter)$"))
                throw new Error(createInvalidValueMessage(pageSize, "page_size", "html-to-pdf", "Allowed values are A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            
            fields.put("page_size", pageSize);
        }

        /**
        * Set the output page width.
        * 
        * @param pageWidth Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setPageWidth(String pageWidth) {
            if (!pageWidth.matches("(?i)^[0-9]*(\\.[0-9]+)?(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(pageWidth, "page_width", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_page_width"), 470);
            
            fields.put("page_width", pageWidth);
        }

        /**
        * Set the output page height.
        * 
        * @param pageHeight Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setPageHeight(String pageHeight) {
            if (!pageHeight.matches("(?i)^[0-9]*(\\.[0-9]+)?(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(pageHeight, "page_height", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_page_height"), 470);
            
            fields.put("page_height", pageHeight);
        }

        /**
        * Set the output page dimensions.
        * 
        * @param width Set the output page width. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        * @param height Set the output page height. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setPageDimensions(String width, String height) {
            this.setPageWidth(width);
            this.setPageHeight(height);
        }

        /**
        * Set the output page orientation.
        * 
        * @param orientation Allowed values are landscape, portrait.
        */
        public void setOrientation(String orientation) {
            if (!orientation.matches("(?i)^(landscape|portrait)$"))
                throw new Error(createInvalidValueMessage(orientation, "orientation", "html-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            
            fields.put("orientation", orientation);
        }

        /**
        * Set the output page top margin.
        * 
        * @param marginTop Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setMarginTop(String marginTop) {
            if (!marginTop.matches("(?i)^[0-9]*(\\.[0-9]+)?(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(marginTop, "margin_top", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_margin_top"), 470);
            
            fields.put("margin_top", marginTop);
        }

        /**
        * Set the output page right margin.
        * 
        * @param marginRight Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setMarginRight(String marginRight) {
            if (!marginRight.matches("(?i)^[0-9]*(\\.[0-9]+)?(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(marginRight, "margin_right", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_margin_right"), 470);
            
            fields.put("margin_right", marginRight);
        }

        /**
        * Set the output page bottom margin.
        * 
        * @param marginBottom Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setMarginBottom(String marginBottom) {
            if (!marginBottom.matches("(?i)^[0-9]*(\\.[0-9]+)?(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(marginBottom, "margin_bottom", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_margin_bottom"), 470);
            
            fields.put("margin_bottom", marginBottom);
        }

        /**
        * Set the output page left margin.
        * 
        * @param marginLeft Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setMarginLeft(String marginLeft) {
            if (!marginLeft.matches("(?i)^[0-9]*(\\.[0-9]+)?(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(marginLeft, "margin_left", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_margin_left"), 470);
            
            fields.put("margin_left", marginLeft);
        }

        /**
        * Disable margins.
        * 
        * @param noMargins Set to <span class='field-value'>true</span> to disable margins.
        */
        public void setNoMargins(boolean noMargins) {
            fields.put("no_margins", noMargins ? "true" : null);
        }

        /**
        * Set the output page margins.
        * 
        * @param top Set the output page top margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        * @param right Set the output page right margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        * @param bottom Set the output page bottom margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        * @param left Set the output page left margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setPageMargins(String top, String right, String bottom, String left) {
            this.setMarginTop(top);
            this.setMarginRight(right);
            this.setMarginBottom(bottom);
            this.setMarginLeft(left);
        }

        /**
        * Load an HTML code from the specified URL and use it as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: <ul> <li><span class='field-value'>pdfcrowd-page-count</span> - the total page count of printed pages</li> <li><span class='field-value'>pdfcrowd-page-number</span> - the current page number</li> <li><span class='field-value'>pdfcrowd-source-url</span> - the source URL of a converted document</li> </ul> The following attributes can be used: <ul> <li><span class='field-value'>data-pdfcrowd-number-format</span> - specifies the type of the used numerals <ul> <li>Arabic numerals are used by default.</li> <li>Roman numerals can be generated by the <span class='field-value'>roman</span> and <span class='field-value'>roman-lowercase</span> values</li> <li>Example: &lt;span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'&gt;&lt;/span&gt;</li> </ul> </li> <li><span class='field-value'>data-pdfcrowd-placement</span> - specifies where to place the source URL, allowed values: <ul> <li>The URL is inserted to the content <ul> <li> Example: &lt;span class='pdfcrowd-source-url'&gt;&lt;/span&gt;<br> will produce &lt;span&gt;http://example.com&lt;/span&gt; </li> </ul>
</li> <li><span class='field-value'>href</span> - the URL is set to the href attribute <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'&gt;Link to source&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;Link to source&lt;/a&gt; </li> </ul> </li> <li><span class='field-value'>href-and-content</span> - the URL is set to the href attribute and to the content <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'&gt;&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;http://example.com&lt;/a&gt; </li> </ul> </li> </ul> </li> </ul>
        * 
        * @param headerUrl The supported protocols are http:// and https://.
        */
        public void setHeaderUrl(String headerUrl) {
            if (!headerUrl.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(headerUrl, "header_url", "html-to-pdf", "The supported protocols are http:// and https://.", "set_header_url"), 470);
            
            fields.put("header_url", headerUrl);
        }

        /**
        * Use the specified HTML code as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: <ul> <li><span class='field-value'>pdfcrowd-page-count</span> - the total page count of printed pages</li> <li><span class='field-value'>pdfcrowd-page-number</span> - the current page number</li> <li><span class='field-value'>pdfcrowd-source-url</span> - the source URL of a converted document</li> </ul> The following attributes can be used: <ul> <li><span class='field-value'>data-pdfcrowd-number-format</span> - specifies the type of the used numerals <ul> <li>Arabic numerals are used by default.</li> <li>Roman numerals can be generated by the <span class='field-value'>roman</span> and <span class='field-value'>roman-lowercase</span> values</li> <li>Example: &lt;span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'&gt;&lt;/span&gt;</li> </ul> </li> <li><span class='field-value'>data-pdfcrowd-placement</span> - specifies where to place the source URL, allowed values: <ul> <li>The URL is inserted to the content <ul> <li> Example: &lt;span class='pdfcrowd-source-url'&gt;&lt;/span&gt;<br> will produce &lt;span&gt;http://example.com&lt;/span&gt; </li> </ul>
</li> <li><span class='field-value'>href</span> - the URL is set to the href attribute <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'&gt;Link to source&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;Link to source&lt;/a&gt; </li> </ul> </li> <li><span class='field-value'>href-and-content</span> - the URL is set to the href attribute and to the content <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'&gt;&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;http://example.com&lt;/a&gt; </li> </ul> </li> </ul> </li> </ul>
        * 
        * @param headerHtml The string must not be empty.
        */
        public void setHeaderHtml(String headerHtml) {
            if (!(headerHtml != null && !headerHtml.isEmpty()))
                throw new Error(createInvalidValueMessage(headerHtml, "header_html", "html-to-pdf", "The string must not be empty.", "set_header_html"), 470);
            
            fields.put("header_html", headerHtml);
        }

        /**
        * Set the header height.
        * 
        * @param headerHeight Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setHeaderHeight(String headerHeight) {
            if (!headerHeight.matches("(?i)^[0-9]*(\\.[0-9]+)?(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(headerHeight, "header_height", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_header_height"), 470);
            
            fields.put("header_height", headerHeight);
        }

        /**
        * Load an HTML code from the specified URL and use it as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: <ul> <li><span class='field-value'>pdfcrowd-page-count</span> - the total page count of printed pages</li> <li><span class='field-value'>pdfcrowd-page-number</span> - the current page number</li> <li><span class='field-value'>pdfcrowd-source-url</span> - the source URL of a converted document</li> </ul> The following attributes can be used: <ul> <li><span class='field-value'>data-pdfcrowd-number-format</span> - specifies the type of the used numerals <ul> <li>Arabic numerals are used by default.</li> <li>Roman numerals can be generated by the <span class='field-value'>roman</span> and <span class='field-value'>roman-lowercase</span> values</li> <li>Example: &lt;span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'&gt;&lt;/span&gt;</li> </ul> </li> <li><span class='field-value'>data-pdfcrowd-placement</span> - specifies where to place the source URL, allowed values: <ul> <li>The URL is inserted to the content <ul> <li> Example: &lt;span class='pdfcrowd-source-url'&gt;&lt;/span&gt;<br> will produce &lt;span&gt;http://example.com&lt;/span&gt; </li> </ul>
</li> <li><span class='field-value'>href</span> - the URL is set to the href attribute <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'&gt;Link to source&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;Link to source&lt;/a&gt; </li> </ul> </li> <li><span class='field-value'>href-and-content</span> - the URL is set to the href attribute and to the content <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'&gt;&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;http://example.com&lt;/a&gt; </li> </ul> </li> </ul> </li> </ul>
        * 
        * @param footerUrl The supported protocols are http:// and https://.
        */
        public void setFooterUrl(String footerUrl) {
            if (!footerUrl.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(footerUrl, "footer_url", "html-to-pdf", "The supported protocols are http:// and https://.", "set_footer_url"), 470);
            
            fields.put("footer_url", footerUrl);
        }

        /**
        * Use the specified HTML as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: <ul> <li><span class='field-value'>pdfcrowd-page-count</span> - the total page count of printed pages</li> <li><span class='field-value'>pdfcrowd-page-number</span> - the current page number</li> <li><span class='field-value'>pdfcrowd-source-url</span> - the source URL of a converted document</li> </ul> The following attributes can be used: <ul> <li><span class='field-value'>data-pdfcrowd-number-format</span> - specifies the type of the used numerals <ul> <li>Arabic numerals are used by default.</li> <li>Roman numerals can be generated by the <span class='field-value'>roman</span> and <span class='field-value'>roman-lowercase</span> values</li> <li>Example: &lt;span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'&gt;&lt;/span&gt;</li> </ul> </li> <li><span class='field-value'>data-pdfcrowd-placement</span> - specifies where to place the source URL, allowed values: <ul> <li>The URL is inserted to the content <ul> <li> Example: &lt;span class='pdfcrowd-source-url'&gt;&lt;/span&gt;<br> will produce &lt;span&gt;http://example.com&lt;/span&gt; </li> </ul>
</li> <li><span class='field-value'>href</span> - the URL is set to the href attribute <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'&gt;Link to source&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;Link to source&lt;/a&gt; </li> </ul> </li> <li><span class='field-value'>href-and-content</span> - the URL is set to the href attribute and to the content <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'&gt;&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;http://example.com&lt;/a&gt; </li> </ul> </li> </ul> </li> </ul>
        * 
        * @param footerHtml The string must not be empty.
        */
        public void setFooterHtml(String footerHtml) {
            if (!(footerHtml != null && !footerHtml.isEmpty()))
                throw new Error(createInvalidValueMessage(footerHtml, "footer_html", "html-to-pdf", "The string must not be empty.", "set_footer_html"), 470);
            
            fields.put("footer_html", footerHtml);
        }

        /**
        * Set the footer height.
        * 
        * @param footerHeight Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        */
        public void setFooterHeight(String footerHeight) {
            if (!footerHeight.matches("(?i)^[0-9]*(\\.[0-9]+)?(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(footerHeight, "footer_height", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_footer_height"), 470);
            
            fields.put("footer_height", footerHeight);
        }

        /**
        * Set the page range to print.
        * 
        * @param pages A comma seperated list of page numbers or ranges.
        */
        public void setPrintPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "pages", "html-to-pdf", "A comma seperated list of page numbers or ranges.", "set_print_page_range"), 470);
            
            fields.put("print_page_range", pages);
        }

        /**
        * Apply the first page of the watermark PDF to every page of the output PDF.
        * 
        * @param pageWatermark The file path to a local watermark PDF file. The file must exist and not be empty.
        */
        public void setPageWatermark(String pageWatermark) {
            if (!(new File(pageWatermark).length() > 0))
                throw new Error(createInvalidValueMessage(pageWatermark, "page_watermark", "html-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            
            files.put("page_watermark", pageWatermark);
        }

        /**
        * Apply each page of the specified watermark PDF to the corresponding page of the output PDF.
        * 
        * @param multipageWatermark The file path to a local watermark PDF file. The file must exist and not be empty.
        */
        public void setMultipageWatermark(String multipageWatermark) {
            if (!(new File(multipageWatermark).length() > 0))
                throw new Error(createInvalidValueMessage(multipageWatermark, "multipage_watermark", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            
            files.put("multipage_watermark", multipageWatermark);
        }

        /**
        * Apply the first page of the specified PDF to the background of every page of the output PDF.
        * 
        * @param pageBackground The file path to a local background PDF file. The file must exist and not be empty.
        */
        public void setPageBackground(String pageBackground) {
            if (!(new File(pageBackground).length() > 0))
                throw new Error(createInvalidValueMessage(pageBackground, "page_background", "html-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            
            files.put("page_background", pageBackground);
        }

        /**
        * Apply each page of the specified PDF to the background of the corresponding page of the output PDF.
        * 
        * @param multipageBackground The file path to a local background PDF file. The file must exist and not be empty.
        */
        public void setMultipageBackground(String multipageBackground) {
            if (!(new File(multipageBackground).length() > 0))
                throw new Error(createInvalidValueMessage(multipageBackground, "multipage_background", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            
            files.put("multipage_background", multipageBackground);
        }

        /**
        * The page header is not printed on the specified pages.
        * 
        * @param pages List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma seperated list of page numbers.
        */
        public void setExcludeHeaderOnPages(String pages) {
            if (!pages.matches("^(?:\\s*\\-?\\d+\\s*,)*\\s*\\-?\\d+\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "pages", "html-to-pdf", "A comma seperated list of page numbers.", "set_exclude_header_on_pages"), 470);
            
            fields.put("exclude_header_on_pages", pages);
        }

        /**
        * The page footer is not printed on the specified pages.
        * 
        * @param pages List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma seperated list of page numbers.
        */
        public void setExcludeFooterOnPages(String pages) {
            if (!pages.matches("^(?:\\s*\\-?\\d+\\s*,)*\\s*\\-?\\d+\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "pages", "html-to-pdf", "A comma seperated list of page numbers.", "set_exclude_footer_on_pages"), 470);
            
            fields.put("exclude_footer_on_pages", pages);
        }

        /**
        * Set an offset between physical and logical page numbers.
        * 
        * @param offset Integer specifying page offset.
        */
        public void setPageNumberingOffset(int offset) {
            fields.put("page_numbering_offset", Integer.toString(offset));
        }

        /**
        * Do not print the background graphics.
        * 
        * @param noBackground Set to <span class='field-value'>true</span> to disable the background graphics.
        */
        public void setNoBackground(boolean noBackground) {
            fields.put("no_background", noBackground ? "true" : null);
        }

        /**
        * Do not execute JavaScript.
        * 
        * @param disableJavascript Set to <span class='field-value'>true</span> to disable JavaScript in web pages.
        */
        public void setDisableJavascript(boolean disableJavascript) {
            fields.put("disable_javascript", disableJavascript ? "true" : null);
        }

        /**
        * Do not load images.
        * 
        * @param disableImageLoading Set to <span class='field-value'>true</span> to disable loading of images.
        */
        public void setDisableImageLoading(boolean disableImageLoading) {
            fields.put("disable_image_loading", disableImageLoading ? "true" : null);
        }

        /**
        * Disable loading fonts from remote sources.
        * 
        * @param disableRemoteFonts Set to <span class='field-value'>true</span> disable loading remote fonts.
        */
        public void setDisableRemoteFonts(boolean disableRemoteFonts) {
            fields.put("disable_remote_fonts", disableRemoteFonts ? "true" : null);
        }

        /**
        * Set the default HTML content text encoding.
        * 
        * @param defaultEncoding The text encoding of the HTML content.
        */
        public void setDefaultEncoding(String defaultEncoding) {
            fields.put("default_encoding", defaultEncoding);
        }

        /**
        * Set the HTTP authentication user name.
        * 
        * @param userName The user name.
        */
        public void setHttpAuthUserName(String userName) {
            fields.put("http_auth_user_name", userName);
        }

        /**
        * Set the HTTP authentication password.
        * 
        * @param password The password.
        */
        public void setHttpAuthPassword(String password) {
            fields.put("http_auth_password", password);
        }

        /**
        * Set the HTTP authentication.
        * 
        * @param userName Set the HTTP authentication user name.
        * @param password Set the HTTP authentication password.
        */
        public void setHttpAuth(String userName, String password) {
            this.setHttpAuthUserName(userName);
            this.setHttpAuthPassword(password);
        }

        /**
        * Use the print version of the page if available (@media print).
        * 
        * @param usePrintMedia Set to <span class='field-value'>true</span> to use the print version of the page.
        */
        public void setUsePrintMedia(boolean usePrintMedia) {
            fields.put("use_print_media", usePrintMedia ? "true" : null);
        }

        /**
        * Do not send the X-Pdfcrowd HTTP header in Pdfcrowd HTTP requests.
        * 
        * @param noXpdfcrowdHeader Set to <span class='field-value'>true</span> to disable sending X-Pdfcrowd HTTP header.
        */
        public void setNoXpdfcrowdHeader(boolean noXpdfcrowdHeader) {
            fields.put("no_xpdfcrowd_header", noXpdfcrowdHeader ? "true" : null);
        }

        /**
        * Set cookies that are sent in Pdfcrowd HTTP requests.
        * 
        * @param cookies The cookie string.
        */
        public void setCookies(String cookies) {
            fields.put("cookies", cookies);
        }

        /**
        * Do not allow insecure HTTPS connections.
        * 
        * @param verifySslCertificates Set to <span class='field-value'>true</span> to enable SSL certificate verification.
        */
        public void setVerifySslCertificates(boolean verifySslCertificates) {
            fields.put("verify_ssl_certificates", verifySslCertificates ? "true" : null);
        }

        /**
        * Abort the conversion if the main URL HTTP status code is greater than or equal to 400.
        * 
        * @param failOnError Set to <span class='field-value'>true</span> to abort the conversion.
        */
        public void setFailOnMainUrlError(boolean failOnError) {
            fields.put("fail_on_main_url_error", failOnError ? "true" : null);
        }

        /**
        * Abort the conversion if any of the sub-request HTTP status code is greater than or equal to 400.
        * 
        * @param failOnError Set to <span class='field-value'>true</span> to abort the conversion.
        */
        public void setFailOnAnyUrlError(boolean failOnError) {
            fields.put("fail_on_any_url_error", failOnError ? "true" : null);
        }

        /**
        * Run a custom JavaScript after the document is loaded. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...).
        * 
        * @param customJavascript String containing a JavaScript code. The string must not be empty.
        */
        public void setCustomJavascript(String customJavascript) {
            if (!(customJavascript != null && !customJavascript.isEmpty()))
                throw new Error(createInvalidValueMessage(customJavascript, "custom_javascript", "html-to-pdf", "The string must not be empty.", "set_custom_javascript"), 470);
            
            fields.put("custom_javascript", customJavascript);
        }

        /**
        * Set a custom HTTP header that is sent in Pdfcrowd HTTP requests.
        * 
        * @param customHttpHeader A string containing the header name and value separated by a colon.
        */
        public void setCustomHttpHeader(String customHttpHeader) {
            if (!customHttpHeader.matches("^.+:.+$"))
                throw new Error(createInvalidValueMessage(customHttpHeader, "custom_http_header", "html-to-pdf", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            
            fields.put("custom_http_header", customHttpHeader);
        }

        /**
        * Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. The maximum value is determined by your API license.
        * 
        * @param javascriptDelay The number of milliseconds to wait. Must be a positive integer number or 0.
        */
        public void setJavascriptDelay(int javascriptDelay) {
            if (!(javascriptDelay >= 0))
                throw new Error(createInvalidValueMessage(javascriptDelay, "javascript_delay", "html-to-pdf", "Must be a positive integer number or 0.", "set_javascript_delay"), 470);
            
            fields.put("javascript_delay", Integer.toString(javascriptDelay));
        }

        /**
        * Convert only the specified element and its children. The element is specified by one or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a>. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
        * 
        * @param selectors One or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a> separated by commas. The string must not be empty.
        */
        public void setElementToConvert(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "selectors", "html-to-pdf", "The string must not be empty.", "set_element_to_convert"), 470);
            
            fields.put("element_to_convert", selectors);
        }

        /**
        * Specify the DOM handling when only a part of the document is converted.
        * 
        * @param mode Allowed values are cut-out, remove-siblings, hide-siblings.
        */
        public void setElementToConvertMode(String mode) {
            if (!mode.matches("(?i)^(cut-out|remove-siblings|hide-siblings)$"))
                throw new Error(createInvalidValueMessage(mode, "mode", "html-to-pdf", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            
            fields.put("element_to_convert_mode", mode);
        }

        /**
        * Wait for the specified element in a source document. The element is specified by one or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a>. If the element is not found, the conversion fails.
        * 
        * @param selectors One or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a> separated by commas. The string must not be empty.
        */
        public void setWaitForElement(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "selectors", "html-to-pdf", "The string must not be empty.", "set_wait_for_element"), 470);
            
            fields.put("wait_for_element", selectors);
        }

        /**
        * Set the viewport width in pixels. The viewport is the user's visible area of the page.
        * 
        * @param viewportWidth The value must be in a range 96-7680.
        */
        public void setViewportWidth(int viewportWidth) {
            if (!(viewportWidth >= 96 && viewportWidth <= 7680))
                throw new Error(createInvalidValueMessage(viewportWidth, "viewport_width", "html-to-pdf", "The value must be in a range 96-7680.", "set_viewport_width"), 470);
            
            fields.put("viewport_width", Integer.toString(viewportWidth));
        }

        /**
        * Set the viewport height in pixels. The viewport is the user's visible area of the page.
        * 
        * @param viewportHeight Must be a positive integer number.
        */
        public void setViewportHeight(int viewportHeight) {
            if (!(viewportHeight > 0))
                throw new Error(createInvalidValueMessage(viewportHeight, "viewport_height", "html-to-pdf", "Must be a positive integer number.", "set_viewport_height"), 470);
            
            fields.put("viewport_height", Integer.toString(viewportHeight));
        }

        /**
        * Set the viewport size. The viewport is the user's visible area of the page.
        * 
        * @param width Set the viewport width in pixels. The viewport is the user's visible area of the page. The value must be in a range 96-7680.
        * @param height Set the viewport height in pixels. The viewport is the user's visible area of the page. Must be a positive integer number.
        */
        public void setViewport(int width, int height) {
            this.setViewportWidth(width);
            this.setViewportHeight(height);
        }

        /**
        * Sets the rendering mode.
        * 
        * @param renderingMode The rendering mode. Allowed values are default, viewport.
        */
        public void setRenderingMode(String renderingMode) {
            if (!renderingMode.matches("(?i)^(default|viewport)$"))
                throw new Error(createInvalidValueMessage(renderingMode, "rendering_mode", "html-to-pdf", "Allowed values are default, viewport.", "set_rendering_mode"), 470);
            
            fields.put("rendering_mode", renderingMode);
        }

        /**
        * Set the scaling factor (zoom) for the main page area.
        * 
        * @param scaleFactor The scale factor. The value must be in a range 10-500.
        */
        public void setScaleFactor(int scaleFactor) {
            if (!(scaleFactor >= 10 && scaleFactor <= 500))
                throw new Error(createInvalidValueMessage(scaleFactor, "scale_factor", "html-to-pdf", "The value must be in a range 10-500.", "set_scale_factor"), 470);
            
            fields.put("scale_factor", Integer.toString(scaleFactor));
        }

        /**
        * Set the scaling factor (zoom) for the header and footer.
        * 
        * @param headerFooterScaleFactor The scale factor. The value must be in a range 10-500.
        */
        public void setHeaderFooterScaleFactor(int headerFooterScaleFactor) {
            if (!(headerFooterScaleFactor >= 10 && headerFooterScaleFactor <= 500))
                throw new Error(createInvalidValueMessage(headerFooterScaleFactor, "header_footer_scale_factor", "html-to-pdf", "The value must be in a range 10-500.", "set_header_footer_scale_factor"), 470);
            
            fields.put("header_footer_scale_factor", Integer.toString(headerFooterScaleFactor));
        }

        /**
        * Create linearized PDF. This is also known as Fast Web View.
        * 
        * @param linearize Set to <span class='field-value'>true</span> to create linearized PDF.
        */
        public void setLinearize(boolean linearize) {
            fields.put("linearize", linearize ? "true" : null);
        }

        /**
        * Encrypt the PDF. This prevents search engines from indexing the contents.
        * 
        * @param encrypt Set to <span class='field-value'>true</span> to enable PDF encryption.
        */
        public void setEncrypt(boolean encrypt) {
            fields.put("encrypt", encrypt ? "true" : null);
        }

        /**
        * Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        * 
        * @param userPassword The user password.
        */
        public void setUserPassword(String userPassword) {
            fields.put("user_password", userPassword);
        }

        /**
        * Protect the PDF with an owner password.  Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        * 
        * @param ownerPassword The owner password.
        */
        public void setOwnerPassword(String ownerPassword) {
            fields.put("owner_password", ownerPassword);
        }

        /**
        * Disallow printing of the output PDF.
        * 
        * @param noPrint Set to <span class='field-value'>true</span> to set the no-print flag in the output PDF.
        */
        public void setNoPrint(boolean noPrint) {
            fields.put("no_print", noPrint ? "true" : null);
        }

        /**
        * Disallow modification of the ouput PDF.
        * 
        * @param noModify Set to <span class='field-value'>true</span> to set the read-only only flag in the output PDF.
        */
        public void setNoModify(boolean noModify) {
            fields.put("no_modify", noModify ? "true" : null);
        }

        /**
        * Disallow text and graphics extraction from the output PDF.
        * 
        * @param noCopy Set to <span class='field-value'>true</span> to set the no-copy flag in the output PDF.
        */
        public void setNoCopy(boolean noCopy) {
            fields.put("no_copy", noCopy ? "true" : null);
        }

        /**
        * Turn on the debug logging.
        * 
        * @param debugLog Set to <span class='field-value'>true</span> to enable the debug logging.
        */
        public void setDebugLog(boolean debugLog) {
            fields.put("debug_log", debugLog ? "true" : null);
        }

        /**
        * Get the URL of the debug log for the last conversion.
        * @return The link to the debug log.
        */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
        * Get the number of conversion credits available in your <a href='/user/account/'>account</a>.
        * The returned value can differ from the actual count if you run parallel conversions.
        * The special value <span class='field-value'>999999</span> is returned if the information is not available.
        * @return The number of credits.
        */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
        * Get the number of credits consumed by the last conversion.
        * @return The number of credits.
        */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
        * Get the job id.
        * @return The unique job identifier.
        */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
        * Get the total number of pages in the output document.
        * @return The page count.
        */
        public int getPageCount() {
            return helper.getPageCount();
        }

        /**
        * Get the size of the output in bytes.
        * @return The count of bytes.
        */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * 
        * @param useHttp Set to <span class='field-value'>true</span> to use HTTP.
        */
        public void setUseHttp(boolean useHttp) {
            this.helper.setUseHttp(useHttp);
        }

        /**
        * Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
        * 
        * @param userAgent The user agent string.
        */
        public void setUserAgent(String userAgent) {
            helper.setUserAgent(userAgent);
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        * 
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        */
        public void setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
        }

    }

    /**
    * Conversion from HTML to image.
    */
    public static final class HtmlToImageClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;
        
        /**
        * Constructor for the Pdfcrowd API client.
        * 
        * @param userName Your username at Pdfcrowd.
        * @param apiKey Your API key.
        */
        public HtmlToImageClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "html");
            fields.put("output_format", "png");
        }

        /**
        * The format of the output file.
        * 
        * @param outputFormat Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
        */
        public void setOutputFormat(String outputFormat) {
            if (!outputFormat.matches("(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$"))
                throw new Error(createInvalidValueMessage(outputFormat, "output_format", "html-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            
            fields.put("output_format", outputFormat);
        }

        /**
        * Convert a web page.
        * 
        * @param url The address of the web page to convert. The supported protocols are http:// and https://.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "url", "html-to-image", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a web page and write the result to an output stream.
        * 
        * @param url The address of the web page to convert. The supported protocols are http:// and https://.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "url", "html-to-image", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a web page and write the result to a local file.
        * 
        * @param url The address of the web page to convert. The supported protocols are http:// and https://.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "html-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertUrlToStream(url, outputFile);
            outputFile.close();
        }

        /**
        * Convert a local file.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip).<br> If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "html-to-image", "The file name must have a valid extension.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a local file and write the result to an output stream.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip).<br> If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "html-to-image", "The file name must have a valid extension.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a local file and write the result to a local file.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip).<br> If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "html-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertFileToStream(file, outputFile);
            outputFile.close();
        }

        /**
        * Convert a string.
        * 
        * @param text The string content to convert. The string must not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertString(String text) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "text", "html-to-image", "The string must not be empty.", "convert_string"), 470);
            
            fields.put("text", text);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a string and write the output to an output stream.
        * 
        * @param text The string content to convert. The string must not be empty.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertStringToStream(String text, OutputStream outStream) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470);
            
            fields.put("text", text);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a string and write the output to a file.
        * 
        * @param text The string content to convert. The string must not be empty.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertStringToFile(String text, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "html-to-image", "The string must not be empty.", "convert_string_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertStringToStream(text, outputFile);
            outputFile.close();
        }

        /**
        * Do not print the background graphics.
        * 
        * @param noBackground Set to <span class='field-value'>true</span> to disable the background graphics.
        */
        public void setNoBackground(boolean noBackground) {
            fields.put("no_background", noBackground ? "true" : null);
        }

        /**
        * Do not execute JavaScript.
        * 
        * @param disableJavascript Set to <span class='field-value'>true</span> to disable JavaScript in web pages.
        */
        public void setDisableJavascript(boolean disableJavascript) {
            fields.put("disable_javascript", disableJavascript ? "true" : null);
        }

        /**
        * Do not load images.
        * 
        * @param disableImageLoading Set to <span class='field-value'>true</span> to disable loading of images.
        */
        public void setDisableImageLoading(boolean disableImageLoading) {
            fields.put("disable_image_loading", disableImageLoading ? "true" : null);
        }

        /**
        * Disable loading fonts from remote sources.
        * 
        * @param disableRemoteFonts Set to <span class='field-value'>true</span> disable loading remote fonts.
        */
        public void setDisableRemoteFonts(boolean disableRemoteFonts) {
            fields.put("disable_remote_fonts", disableRemoteFonts ? "true" : null);
        }

        /**
        * Set the default HTML content text encoding.
        * 
        * @param defaultEncoding The text encoding of the HTML content.
        */
        public void setDefaultEncoding(String defaultEncoding) {
            fields.put("default_encoding", defaultEncoding);
        }

        /**
        * Set the HTTP authentication user name.
        * 
        * @param userName The user name.
        */
        public void setHttpAuthUserName(String userName) {
            fields.put("http_auth_user_name", userName);
        }

        /**
        * Set the HTTP authentication password.
        * 
        * @param password The password.
        */
        public void setHttpAuthPassword(String password) {
            fields.put("http_auth_password", password);
        }

        /**
        * Set the HTTP authentication.
        * 
        * @param userName Set the HTTP authentication user name.
        * @param password Set the HTTP authentication password.
        */
        public void setHttpAuth(String userName, String password) {
            this.setHttpAuthUserName(userName);
            this.setHttpAuthPassword(password);
        }

        /**
        * Use the print version of the page if available (@media print).
        * 
        * @param usePrintMedia Set to <span class='field-value'>true</span> to use the print version of the page.
        */
        public void setUsePrintMedia(boolean usePrintMedia) {
            fields.put("use_print_media", usePrintMedia ? "true" : null);
        }

        /**
        * Do not send the X-Pdfcrowd HTTP header in Pdfcrowd HTTP requests.
        * 
        * @param noXpdfcrowdHeader Set to <span class='field-value'>true</span> to disable sending X-Pdfcrowd HTTP header.
        */
        public void setNoXpdfcrowdHeader(boolean noXpdfcrowdHeader) {
            fields.put("no_xpdfcrowd_header", noXpdfcrowdHeader ? "true" : null);
        }

        /**
        * Set cookies that are sent in Pdfcrowd HTTP requests.
        * 
        * @param cookies The cookie string.
        */
        public void setCookies(String cookies) {
            fields.put("cookies", cookies);
        }

        /**
        * Do not allow insecure HTTPS connections.
        * 
        * @param verifySslCertificates Set to <span class='field-value'>true</span> to enable SSL certificate verification.
        */
        public void setVerifySslCertificates(boolean verifySslCertificates) {
            fields.put("verify_ssl_certificates", verifySslCertificates ? "true" : null);
        }

        /**
        * Abort the conversion if the main URL HTTP status code is greater than or equal to 400.
        * 
        * @param failOnError Set to <span class='field-value'>true</span> to abort the conversion.
        */
        public void setFailOnMainUrlError(boolean failOnError) {
            fields.put("fail_on_main_url_error", failOnError ? "true" : null);
        }

        /**
        * Abort the conversion if any of the sub-request HTTP status code is greater than or equal to 400.
        * 
        * @param failOnError Set to <span class='field-value'>true</span> to abort the conversion.
        */
        public void setFailOnAnyUrlError(boolean failOnError) {
            fields.put("fail_on_any_url_error", failOnError ? "true" : null);
        }

        /**
        * Run a custom JavaScript after the document is loaded. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...).
        * 
        * @param customJavascript String containing a JavaScript code. The string must not be empty.
        */
        public void setCustomJavascript(String customJavascript) {
            if (!(customJavascript != null && !customJavascript.isEmpty()))
                throw new Error(createInvalidValueMessage(customJavascript, "custom_javascript", "html-to-image", "The string must not be empty.", "set_custom_javascript"), 470);
            
            fields.put("custom_javascript", customJavascript);
        }

        /**
        * Set a custom HTTP header that is sent in Pdfcrowd HTTP requests.
        * 
        * @param customHttpHeader A string containing the header name and value separated by a colon.
        */
        public void setCustomHttpHeader(String customHttpHeader) {
            if (!customHttpHeader.matches("^.+:.+$"))
                throw new Error(createInvalidValueMessage(customHttpHeader, "custom_http_header", "html-to-image", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            
            fields.put("custom_http_header", customHttpHeader);
        }

        /**
        * Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. The maximum value is determined by your API license.
        * 
        * @param javascriptDelay The number of milliseconds to wait. Must be a positive integer number or 0.
        */
        public void setJavascriptDelay(int javascriptDelay) {
            if (!(javascriptDelay >= 0))
                throw new Error(createInvalidValueMessage(javascriptDelay, "javascript_delay", "html-to-image", "Must be a positive integer number or 0.", "set_javascript_delay"), 470);
            
            fields.put("javascript_delay", Integer.toString(javascriptDelay));
        }

        /**
        * Convert only the specified element and its children. The element is specified by one or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a>. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
        * 
        * @param selectors One or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a> separated by commas. The string must not be empty.
        */
        public void setElementToConvert(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "selectors", "html-to-image", "The string must not be empty.", "set_element_to_convert"), 470);
            
            fields.put("element_to_convert", selectors);
        }

        /**
        * Specify the DOM handling when only a part of the document is converted.
        * 
        * @param mode Allowed values are cut-out, remove-siblings, hide-siblings.
        */
        public void setElementToConvertMode(String mode) {
            if (!mode.matches("(?i)^(cut-out|remove-siblings|hide-siblings)$"))
                throw new Error(createInvalidValueMessage(mode, "mode", "html-to-image", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            
            fields.put("element_to_convert_mode", mode);
        }

        /**
        * Wait for the specified element in a source document. The element is specified by one or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a>. If the element is not found, the conversion fails.
        * 
        * @param selectors One or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a> separated by commas. The string must not be empty.
        */
        public void setWaitForElement(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "selectors", "html-to-image", "The string must not be empty.", "set_wait_for_element"), 470);
            
            fields.put("wait_for_element", selectors);
        }

        /**
        * Set the output image width in pixels.
        * 
        * @param screenshotWidth The value must be in a range 96-7680.
        */
        public void setScreenshotWidth(int screenshotWidth) {
            if (!(screenshotWidth >= 96 && screenshotWidth <= 7680))
                throw new Error(createInvalidValueMessage(screenshotWidth, "screenshot_width", "html-to-image", "The value must be in a range 96-7680.", "set_screenshot_width"), 470);
            
            fields.put("screenshot_width", Integer.toString(screenshotWidth));
        }

        /**
        * Set the output image height in pixels. If it's not specified, actual document height is used.
        * 
        * @param screenshotHeight Must be a positive integer number.
        */
        public void setScreenshotHeight(int screenshotHeight) {
            if (!(screenshotHeight > 0))
                throw new Error(createInvalidValueMessage(screenshotHeight, "screenshot_height", "html-to-image", "Must be a positive integer number.", "set_screenshot_height"), 470);
            
            fields.put("screenshot_height", Integer.toString(screenshotHeight));
        }

        /**
        * Turn on the debug logging.
        * 
        * @param debugLog Set to <span class='field-value'>true</span> to enable the debug logging.
        */
        public void setDebugLog(boolean debugLog) {
            fields.put("debug_log", debugLog ? "true" : null);
        }

        /**
        * Get the URL of the debug log for the last conversion.
        * @return The link to the debug log.
        */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
        * Get the number of conversion credits available in your <a href='/user/account/'>account</a>.
        * The returned value can differ from the actual count if you run parallel conversions.
        * The special value <span class='field-value'>999999</span> is returned if the information is not available.
        * @return The number of credits.
        */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
        * Get the number of credits consumed by the last conversion.
        * @return The number of credits.
        */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
        * Get the job id.
        * @return The unique job identifier.
        */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
        * Get the size of the output in bytes.
        * @return The count of bytes.
        */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * 
        * @param useHttp Set to <span class='field-value'>true</span> to use HTTP.
        */
        public void setUseHttp(boolean useHttp) {
            this.helper.setUseHttp(useHttp);
        }

        /**
        * Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
        * 
        * @param userAgent The user agent string.
        */
        public void setUserAgent(String userAgent) {
            helper.setUserAgent(userAgent);
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        * 
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        */
        public void setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
        }

    }

    /**
    * Conversion from one image format to another image format.
    */
    public static final class ImageToImageClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;
        
        /**
        * Constructor for the Pdfcrowd API client.
        * 
        * @param userName Your username at Pdfcrowd.
        * @param apiKey Your API key.
        */
        public ImageToImageClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "image");
            fields.put("output_format", "png");
        }

        /**
        * Convert an image.
        * 
        * @param url The address of the image to convert. The supported protocols are http:// and https://.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "url", "image-to-image", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert an image and write the result to an output stream.
        * 
        * @param url The address of the image to convert. The supported protocols are http:// and https://.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "url", "image-to-image", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert an image and write the result to a local file.
        * 
        * @param url The address of the image to convert. The supported protocols are http:// and https://.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "image-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertUrlToStream(url, outputFile);
            outputFile.close();
        }

        /**
        * Convert a local file.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a local file and write the result to an output stream.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a local file and write the result to a local file.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "image-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertFileToStream(file, outputFile);
            outputFile.close();
        }

        /**
        * Convert raw data.
        * 
        * @param data The raw content to be converted.
        * @return Byte array with the output.
        */
        public byte[] convertRawData(byte[] data) {
            rawData.put("file", data);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert raw data and write the result to an output stream.
        * 
        * @param data The raw content to be converted.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertRawDataToStream(byte[] data, OutputStream outStream) {
            rawData.put("file", data);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert raw data to a file.
        * 
        * @param data The raw content to be converted.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertRawDataToFile(byte[] data, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "image-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertRawDataToStream(data, outputFile);
            outputFile.close();
        }

        /**
        * The format of the output file.
        * 
        * @param outputFormat Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
        */
        public void setOutputFormat(String outputFormat) {
            if (!outputFormat.matches("(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$"))
                throw new Error(createInvalidValueMessage(outputFormat, "output_format", "image-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            
            fields.put("output_format", outputFormat);
        }

        /**
        * Resize the image.
        * 
        * @param resize The resize percentage or new image dimensions.
        */
        public void setResize(String resize) {
            fields.put("resize", resize);
        }

        /**
        * Rotate the image.
        * 
        * @param rotate The rotation specified in degrees.
        */
        public void setRotate(String rotate) {
            fields.put("rotate", rotate);
        }

        /**
        * Turn on the debug logging.
        * 
        * @param debugLog Set to <span class='field-value'>true</span> to enable the debug logging.
        */
        public void setDebugLog(boolean debugLog) {
            fields.put("debug_log", debugLog ? "true" : null);
        }

        /**
        * Get the URL of the debug log for the last conversion.
        * @return The link to the debug log.
        */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
        * Get the number of conversion credits available in your <a href='/user/account/'>account</a>.
        * The returned value can differ from the actual count if you run parallel conversions.
        * The special value <span class='field-value'>999999</span> is returned if the information is not available.
        * @return The number of credits.
        */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
        * Get the number of credits consumed by the last conversion.
        * @return The number of credits.
        */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
        * Get the job id.
        * @return The unique job identifier.
        */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
        * Get the size of the output in bytes.
        * @return The count of bytes.
        */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * 
        * @param useHttp Set to <span class='field-value'>true</span> to use HTTP.
        */
        public void setUseHttp(boolean useHttp) {
            this.helper.setUseHttp(useHttp);
        }

        /**
        * Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
        * 
        * @param userAgent The user agent string.
        */
        public void setUserAgent(String userAgent) {
            helper.setUserAgent(userAgent);
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        * 
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        */
        public void setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
        }

    }

    /**
    * Conversion from PDF to PDF.
    */
    public static final class PdfToPdfClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;
        
        /**
        * Constructor for the Pdfcrowd API client.
        * 
        * @param userName Your username at Pdfcrowd.
        * @param apiKey Your API key.
        */
        public PdfToPdfClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "pdf");
            fields.put("output_format", "pdf");
        }

        /**
        * Specifies the action to be performed on the input PDFs.
        * 
        * @param action Allowed values are join, shuffle.
        */
        public void setAction(String action) {
            if (!action.matches("(?i)^(join|shuffle)$"))
                throw new Error(createInvalidValueMessage(action, "action", "pdf-to-pdf", "Allowed values are join, shuffle.", "set_action"), 470);
            
            fields.put("action", action);
        }

        /**
        * Perform an action on the input files.
        * @return Byte array containing the output PDF.
        */
        public byte[] convertFiles() {
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Perform an action on the input files and write the output PDF to an output stream.
        * 
        * @param outStream The output stream that will contain the output PDF.
        */
        public void convertFilesToStream(OutputStream outStream) {
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Perform an action on the input files and write the output PDF to a file.
        * 
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertFilesToFile(String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "pdf-to-pdf", "The string must not be empty.", "convert_files_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertFilesToStream(outputFile);
            outputFile.close();
        }

        /**
        * Add a PDF file to the list of the input PDFs.
        * 
        * @param filePath The file path to a local PDF file. The file must exist and not be empty.
        */
        public void addPdfFile(String filePath) {
            if (!(new File(filePath).length() > 0))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "pdf-to-pdf", "The file must exist and not be empty.", "add_pdf_file"), 470);
            
            files.put("f_" + Integer.toString(fileId), filePath);
            fileId++;
        }

        /**
        * Add in-memory raw PDF data to the list of the input PDFs.
        * 
        * @param pdfRawData The raw PDF data. The input data must be PDF content.
        */
        public void addPdfRawData(byte[] pdfRawData) {
            if (!(pdfRawData != null && pdfRawData.length > 300 && (new String(pdfRawData, 0, 4).equals("%PDF"))))
                throw new Error(createInvalidValueMessage("raw PDF data", "pdf_raw_data", "pdf-to-pdf", "The input data must be PDF content.", "add_pdf_raw_data"), 470);
            
            rawData.put("f_" + Integer.toString(fileId), pdfRawData);
            fileId++;
        }

        /**
        * Turn on the debug logging.
        * 
        * @param debugLog Set to <span class='field-value'>true</span> to enable the debug logging.
        */
        public void setDebugLog(boolean debugLog) {
            fields.put("debug_log", debugLog ? "true" : null);
        }

        /**
        * Get the URL of the debug log for the last conversion.
        * @return The link to the debug log.
        */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
        * Get the number of conversion credits available in your <a href='/user/account/'>account</a>.
        * The returned value can differ from the actual count if you run parallel conversions.
        * The special value <span class='field-value'>999999</span> is returned if the information is not available.
        * @return The number of credits.
        */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
        * Get the number of credits consumed by the last conversion.
        * @return The number of credits.
        */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
        * Get the job id.
        * @return The unique job identifier.
        */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
        * Get the total number of pages in the output document.
        * @return The page count.
        */
        public int getPageCount() {
            return helper.getPageCount();
        }

        /**
        * Get the size of the output in bytes.
        * @return The count of bytes.
        */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * 
        * @param useHttp Set to <span class='field-value'>true</span> to use HTTP.
        */
        public void setUseHttp(boolean useHttp) {
            this.helper.setUseHttp(useHttp);
        }

        /**
        * Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
        * 
        * @param userAgent The user agent string.
        */
        public void setUserAgent(String userAgent) {
            helper.setUserAgent(userAgent);
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        * 
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        */
        public void setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
        }

    }

    /**
    * Conversion from an image to PDF.
    */
    public static final class ImageToPdfClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;
        
        /**
        * Constructor for the Pdfcrowd API client.
        * 
        * @param userName Your username at Pdfcrowd.
        * @param apiKey Your API key.
        */
        public ImageToPdfClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "image");
            fields.put("output_format", "pdf");
        }

        /**
        * Convert an image.
        * 
        * @param url The address of the image to convert. The supported protocols are http:// and https://.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "url", "image-to-pdf", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert an image and write the result to an output stream.
        * 
        * @param url The address of the image to convert. The supported protocols are http:// and https://.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "url", "image-to-pdf", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert an image and write the result to a local file.
        * 
        * @param url The address of the image to convert. The supported protocols are http:// and https://.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "image-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertUrlToStream(url, outputFile);
            outputFile.close();
        }

        /**
        * Convert a local file.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a local file and write the result to an output stream.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a local file and write the result to a local file.
        * 
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "image-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertFileToStream(file, outputFile);
            outputFile.close();
        }

        /**
        * Convert raw data.
        * 
        * @param data The raw content to be converted.
        * @return Byte array with the output.
        */
        public byte[] convertRawData(byte[] data) {
            rawData.put("file", data);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert raw data and write the result to an output stream.
        * 
        * @param data The raw content to be converted.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertRawDataToStream(byte[] data, OutputStream outStream) {
            rawData.put("file", data);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert raw data to a file.
        * 
        * @param data The raw content to be converted.
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertRawDataToFile(byte[] data, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "file_path", "image-to-pdf", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertRawDataToStream(data, outputFile);
            outputFile.close();
        }

        /**
        * Resize the image.
        * 
        * @param resize The resize percentage or new image dimensions.
        */
        public void setResize(String resize) {
            fields.put("resize", resize);
        }

        /**
        * Rotate the image.
        * 
        * @param rotate The rotation specified in degrees.
        */
        public void setRotate(String rotate) {
            fields.put("rotate", rotate);
        }

        /**
        * Turn on the debug logging.
        * 
        * @param debugLog Set to <span class='field-value'>true</span> to enable the debug logging.
        */
        public void setDebugLog(boolean debugLog) {
            fields.put("debug_log", debugLog ? "true" : null);
        }

        /**
        * Get the URL of the debug log for the last conversion.
        * @return The link to the debug log.
        */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
        * Get the number of conversion credits available in your <a href='/user/account/'>account</a>.
        * The returned value can differ from the actual count if you run parallel conversions.
        * The special value <span class='field-value'>999999</span> is returned if the information is not available.
        * @return The number of credits.
        */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
        * Get the number of credits consumed by the last conversion.
        * @return The number of credits.
        */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
        * Get the job id.
        * @return The unique job identifier.
        */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
        * Get the size of the output in bytes.
        * @return The count of bytes.
        */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * 
        * @param useHttp Set to <span class='field-value'>true</span> to use HTTP.
        */
        public void setUseHttp(boolean useHttp) {
            this.helper.setUseHttp(useHttp);
        }

        /**
        * Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
        * 
        * @param userAgent The user agent string.
        */
        public void setUserAgent(String userAgent) {
            helper.setUserAgent(userAgent);
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        * 
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        */
        public void setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
        }

    }

}
