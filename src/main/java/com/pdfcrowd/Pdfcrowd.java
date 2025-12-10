// Copyright (C) 2009-2018 pdfcrowd.com
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
    public static final String CLIENT_VERSION = "6.5.4";

    public static final class Error extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public int statusCode = 0;
        private int reasonCode = -1;
        private String error;
        private String message;
        private String docLink;

        public Error() {}
        public Error(Throwable throwable) { super(throwable); }
        public Error(String msg) { this(msg, 0); }
        public Error(String msg, int code) {
            super(msg);

            error = msg;

            String pattern = "^(\\d+)\\.(\\d+)\\s+-\\s+(.*?)(?:\\s+Documentation link:\\s+(.*))?$";
            java.util.regex.Pattern regex = java.util.regex.Pattern.compile(pattern, java.util.regex.Pattern.DOTALL);
            java.util.regex.Matcher matcher = regex.matcher(msg);

            if (matcher.find()) {
                statusCode = Integer.parseInt(matcher.group(1));
                reasonCode = Integer.parseInt(matcher.group(2));
                message = matcher.group(3);
                docLink = matcher.group(4) != null ? matcher.group(4) : "";
             } else {
                statusCode = code;
                message = error;
                if (statusCode != 0) {
                    error = statusCode + " - " + msg;
                }
                docLink = "";
            }
        }

        public String toString() {
            return error;
        }

        @Deprecated
        public int getCode() {
            System.err.println("[DEPRECATION] `getCode` is obsolete and will be removed in future versions. Use `getStatusCode` instead.");
            return statusCode;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public int getReasonCode() {
            return reasonCode;
        }

        @Override
        public String getMessage() {
            return message;
        }

        public String getDocumentationLink() {
            return docLink;
        }
    }

    // helper class to use just single array in memory for ZipOutputStream
    public static class ByteArrayIOStream extends InputStream {
        private ByteArrayOutputStream bytesStream = new ByteArrayOutputStream();

        public OutputStream getOutputStream() {
            return bytesStream;
        }

        public byte[] getBytes() {
            return bytesStream.toByteArray();
        }

        // InputStream noop implementation
        public int read() { return -1; }
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
        private int totalPageCount;
        private int outputSize;

        private String proxyHost;
        private int proxyPort;
        private String proxyUserName;
        private String proxyPassword;

        private int retryCount;
        private int retry;
        private String converterVersion;

        ConnectionHelper(String userName, String apiKey) {
            this.userName = userName;
            this.apiKey = apiKey;

            resetResponseData();
            setProxy(null, 0, null, null);
            setUseHttp(false);
            setUserAgent("pdfcrowd_java_client/6.5.4 (https://pdfcrowd.com)");

            retryCount = 1;
            converterVersion = "24.04";
        }

        private void resetResponseData() {
            debugLogUrl = null;
            credits = 999999;
            consumedCredits = 0;
            jobId = "";
            pageCount = 0;
            totalPageCount = 0;
            outputSize = 0;
            retry = 0;
        }

        private static byte[] getBytes(InputStream in) throws IOException {
            if (in instanceof ByteArrayIOStream) {
                return ((ByteArrayIOStream) in).getBytes();
            }

            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            int bytesRead;
            byte[] buffer = new byte[8192];
            while ((bytesRead = in.read(buffer, 0, buffer.length)) != -1) {
                bytes.write(buffer, 0, bytesRead);
            }
            bytes.flush();
            return bytes.toByteArray();
        }

        private static void copyStream(InputStream in, OutputStream out) throws IOException {
            int bytesRead;
            byte[] buffer = new byte[8192];
            while ((bytesRead = in.read(buffer, 0, buffer.length)) != -1) {
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
            ByteArrayOutputStream body = encodeMultipartPostData(prepareFields(fields), files, rawData);
            String contentType = "multipart/form-data; boundary=" + MULTIPART_BOUNDARY;
            return doPost(body, contentType, outStream);
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

                body.add("--" + MULTIPART_BOUNDARY + "--");
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
                URL url = new URL(String.format("http%s://%s:%d%s%s/",
                                                useHttp ? "": "s",
                                                HOST, port,
                                                "/convert/",
                                                this.converterVersion));
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

                    if (!useHttp && (conn instanceof HttpsURLConnection)) {
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
                String authEncoded = new String(Base64Utils.encodeBytes(auth.getBytes()));
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

            while(true) {
                try {
                    return execRequest(body, contentType, outStream);
                }
                catch(Error err) {
                    if ((err.getStatusCode() == 502 || err.getStatusCode() == 503) &&
                        retryCount > retry) {
                        retry++;
                        try {
                            Thread.sleep(retry * 100);
                        }
                        catch (InterruptedException e) {
                            throw err;
                        }
                    } else {
                        throw err;
                    }
                }
            }
        }

        private byte[] execRequest(Object body, String contentType, OutputStream outStream) {
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
                totalPageCount = getIntHeader(conn, "X-Pdfcrowd-Total-Pages", 0);
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
            catch(SSLException e) {
                throw new Error("400.356 - There was a problem connecting to PDFCrowd servers over HTTPS:\n" +
                                e.toString() +
                                "\nYou can still use the API over HTTP, you just need to add the following line right after PDFCrowd client initialization:\nclient.setUseHttp(true);",
                                0);
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

        void setRetryCount(int retryCount) {
            this.retryCount = retryCount;
        }

        void setConverterVersion(String converterVersion) {
            this.converterVersion = converterVersion;
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

        int getTotalPageCount() {
            return totalPageCount;
        }

        int getOutputSize() {
            return outputSize;
        }

        String getConverterVersion() {
            return converterVersion;
        }
    }

    static String createInvalidValueMessage(Object value, String field, String converter, String hint, String id) {
        String message = String.format("400.311 - Invalid value '%s' for the '%s' option.", value, field);
        if(hint != null)
            {
                message += " " + hint;
            }
        return message + " " + String.format("Documentation link: https://www.pdfcrowd.com/api/%s-java/ref/#%s", converter, id);
    }

// generated code

    /**
     * Conversion from HTML to PDF.
     *
     * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/">https://pdfcrowd.com/api/html-to-pdf-java/</a>
     */
    public static final class HtmlToPdfClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#HtmlToPdfClient">https://pdfcrowd.com/api/html-to-pdf-java/ref/#HtmlToPdfClient</a>
         */
        public HtmlToPdfClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "html");
            fields.put("output_format", "pdf");
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_url">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_url</a>
         */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_url_to_stream">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_url_to_stream</a>
         */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_url_to_file">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_url_to_file</a>
         */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertUrlToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertUrlToStream(url, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_file">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_file</a>
         */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_file_to_stream">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_file_to_stream</a>
         */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_file_to_file">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_file_to_file</a>
         */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertFileToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertFileToStream(file, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_string">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_string</a>
         */
        public byte[] convertString(String text) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "convertString", "html-to-pdf", "The string must not be empty.", "convert_string"), 470);
            
            fields.put("text", text);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_string_to_stream">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_string_to_stream</a>
         */
        public void convertStringToStream(String text, OutputStream outStream) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "convertStringToStream::text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470);
            
            fields.put("text", text);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_string_to_file">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_string_to_file</a>
         */
        public void convertStringToFile(String text, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStringToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_string_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStringToStream(text, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_stream">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_stream</a>
         */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_stream_to_stream">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_stream_to_stream</a>
         */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_stream_to_file">https://pdfcrowd.com/api/html-to-pdf-java/ref/#convert_stream_to_file</a>
         */
        public void convertStreamToFile(InputStream inStream, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStreamToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_stream_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStreamToStream(inStream, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_zip_main_filename">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_zip_main_filename</a>
         */
        public HtmlToPdfClient setZipMainFilename(String filename) {
            fields.put("zip_main_filename", filename);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_size">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_size</a>
         */
        public HtmlToPdfClient setPageSize(String size) {
            if (!size.matches("(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$"))
                throw new Error(createInvalidValueMessage(size, "setPageSize", "html-to-pdf", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            
            fields.put("page_size", size);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_width">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_width</a>
         */
        public HtmlToPdfClient setPageWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setPageWidth", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_width"), 470);
            
            fields.put("page_width", width);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_height">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_height</a>
         */
        public HtmlToPdfClient setPageHeight(String height) {
            if (!height.matches("(?i)^0$|^\\-1$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setPageHeight", "html-to-pdf", "The value must be -1 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_height"), 470);
            
            fields.put("page_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_dimensions">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_dimensions</a>
         */
        public HtmlToPdfClient setPageDimensions(String width, String height) {
            this.setPageWidth(width);
            this.setPageHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_orientation">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_orientation</a>
         */
        public HtmlToPdfClient setOrientation(String orientation) {
            if (!orientation.matches("(?i)^(landscape|portrait)$"))
                throw new Error(createInvalidValueMessage(orientation, "setOrientation", "html-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            
            fields.put("orientation", orientation);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_margin_top">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_margin_top</a>
         */
        public HtmlToPdfClient setMarginTop(String top) {
            if (!top.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(top, "setMarginTop", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            
            fields.put("margin_top", top);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_margin_right">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_margin_right</a>
         */
        public HtmlToPdfClient setMarginRight(String right) {
            if (!right.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(right, "setMarginRight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            
            fields.put("margin_right", right);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_margin_bottom">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_margin_bottom</a>
         */
        public HtmlToPdfClient setMarginBottom(String bottom) {
            if (!bottom.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(bottom, "setMarginBottom", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            
            fields.put("margin_bottom", bottom);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_margin_left">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_margin_left</a>
         */
        public HtmlToPdfClient setMarginLeft(String left) {
            if (!left.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(left, "setMarginLeft", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            
            fields.put("margin_left", left);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_margins">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_margins</a>
         */
        public HtmlToPdfClient setNoMargins(boolean value) {
            fields.put("no_margins", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_margins">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_margins</a>
         */
        public HtmlToPdfClient setPageMargins(String top, String right, String bottom, String left) {
            this.setMarginTop(top);
            this.setMarginRight(right);
            this.setMarginBottom(bottom);
            this.setMarginLeft(left);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_print_page_range">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_print_page_range</a>
         */
        public HtmlToPdfClient setPrintPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*)|odd|even|last)\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*)|odd|even|last)\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPrintPageRange", "html-to-pdf", "A comma separated list of page numbers or ranges. Special strings may be used, such as 'odd', 'even' and 'last'.", "set_print_page_range"), 470);
            
            fields.put("print_page_range", pages);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_viewport_width">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_viewport_width</a>
         */
        public HtmlToPdfClient setContentViewportWidth(String width) {
            if (!width.matches("(?i)^(balanced|small|medium|large|extra-large|[0-9]+(px)?)$"))
                throw new Error(createInvalidValueMessage(width, "setContentViewportWidth", "html-to-pdf", "The value must be 'balanced', 'small', 'medium', 'large', 'extra-large', or a number in the range 96-65000px.", "set_content_viewport_width"), 470);
            
            fields.put("content_viewport_width", width);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_viewport_height">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_viewport_height</a>
         */
        public HtmlToPdfClient setContentViewportHeight(String height) {
            if (!height.matches("(?i)^(auto|large|[0-9]+(px)?)$"))
                throw new Error(createInvalidValueMessage(height, "setContentViewportHeight", "html-to-pdf", "The value must be 'auto', 'large', or a number.", "set_content_viewport_height"), 470);
            
            fields.put("content_viewport_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_fit_mode">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_fit_mode</a>
         */
        public HtmlToPdfClient setContentFitMode(String mode) {
            if (!mode.matches("(?i)^(auto|smart-scaling|no-scaling|viewport-width|content-width|single-page|single-page-ratio)$"))
                throw new Error(createInvalidValueMessage(mode, "setContentFitMode", "html-to-pdf", "Allowed values are auto, smart-scaling, no-scaling, viewport-width, content-width, single-page, single-page-ratio.", "set_content_fit_mode"), 470);
            
            fields.put("content_fit_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_remove_blank_pages">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_remove_blank_pages</a>
         */
        public HtmlToPdfClient setRemoveBlankPages(String pages) {
            if (!pages.matches("(?i)^(trailing|all|none)$"))
                throw new Error(createInvalidValueMessage(pages, "setRemoveBlankPages", "html-to-pdf", "Allowed values are trailing, all, none.", "set_remove_blank_pages"), 470);
            
            fields.put("remove_blank_pages", pages);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_url">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_url</a>
         */
        public HtmlToPdfClient setHeaderUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setHeaderUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_header_url"), 470);
            
            fields.put("header_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_html">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_html</a>
         */
        public HtmlToPdfClient setHeaderHtml(String html) {
            if (!(html != null && !html.isEmpty()))
                throw new Error(createInvalidValueMessage(html, "setHeaderHtml", "html-to-pdf", "The string must not be empty.", "set_header_html"), 470);
            
            fields.put("header_html", html);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_height">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_height</a>
         */
        public HtmlToPdfClient setHeaderHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setHeaderHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_header_height"), 470);
            
            fields.put("header_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_zip_header_filename">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_zip_header_filename</a>
         */
        public HtmlToPdfClient setZipHeaderFilename(String filename) {
            fields.put("zip_header_filename", filename);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_footer_url">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_footer_url</a>
         */
        public HtmlToPdfClient setFooterUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setFooterUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_footer_url"), 470);
            
            fields.put("footer_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_footer_html">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_footer_html</a>
         */
        public HtmlToPdfClient setFooterHtml(String html) {
            if (!(html != null && !html.isEmpty()))
                throw new Error(createInvalidValueMessage(html, "setFooterHtml", "html-to-pdf", "The string must not be empty.", "set_footer_html"), 470);
            
            fields.put("footer_html", html);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_footer_height">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_footer_height</a>
         */
        public HtmlToPdfClient setFooterHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setFooterHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_footer_height"), 470);
            
            fields.put("footer_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_zip_footer_filename">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_zip_footer_filename</a>
         */
        public HtmlToPdfClient setZipFooterFilename(String filename) {
            fields.put("zip_footer_filename", filename);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_header_footer_horizontal_margins">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_header_footer_horizontal_margins</a>
         */
        public HtmlToPdfClient setNoHeaderFooterHorizontalMargins(boolean value) {
            fields.put("no_header_footer_horizontal_margins", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_exclude_header_on_pages">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_exclude_header_on_pages</a>
         */
        public HtmlToPdfClient setExcludeHeaderOnPages(String pages) {
            if (!pages.matches("^(?:\\s*\\-?\\d+\\s*,)*\\s*\\-?\\d+\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setExcludeHeaderOnPages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_header_on_pages"), 470);
            
            fields.put("exclude_header_on_pages", pages);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_exclude_footer_on_pages">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_exclude_footer_on_pages</a>
         */
        public HtmlToPdfClient setExcludeFooterOnPages(String pages) {
            if (!pages.matches("^(?:\\s*\\-?\\d+\\s*,)*\\s*\\-?\\d+\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setExcludeFooterOnPages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_footer_on_pages"), 470);
            
            fields.put("exclude_footer_on_pages", pages);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_footer_scale_factor">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_footer_scale_factor</a>
         */
        public HtmlToPdfClient setHeaderFooterScaleFactor(int factor) {
            if (!(factor >= 10 && factor <= 500))
                throw new Error(createInvalidValueMessage(factor, "setHeaderFooterScaleFactor", "html-to-pdf", "The accepted range is 10-500.", "set_header_footer_scale_factor"), 470);
            
            fields.put("header_footer_scale_factor", Integer.toString(factor));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_numbering_offset">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_numbering_offset</a>
         */
        public HtmlToPdfClient setPageNumberingOffset(int offset) {
            fields.put("page_numbering_offset", Integer.toString(offset));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_watermark">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_watermark</a>
         */
        public HtmlToPdfClient setPageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setPageWatermark", "html-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            
            files.put("page_watermark", watermark);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_watermark_url">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_watermark_url</a>
         */
        public HtmlToPdfClient setPageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageWatermarkUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            
            fields.put("page_watermark_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_multipage_watermark">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_multipage_watermark</a>
         */
        public HtmlToPdfClient setMultipageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setMultipageWatermark", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            
            files.put("multipage_watermark", watermark);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_multipage_watermark_url">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_multipage_watermark_url</a>
         */
        public HtmlToPdfClient setMultipageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageWatermarkUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            
            fields.put("multipage_watermark_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_background">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_background</a>
         */
        public HtmlToPdfClient setPageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setPageBackground", "html-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            
            files.put("page_background", background);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_background_url">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_background_url</a>
         */
        public HtmlToPdfClient setPageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageBackgroundUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            
            fields.put("page_background_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_multipage_background">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_multipage_background</a>
         */
        public HtmlToPdfClient setMultipageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setMultipageBackground", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            
            files.put("multipage_background", background);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_multipage_background_url">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_multipage_background_url</a>
         */
        public HtmlToPdfClient setMultipageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageBackgroundUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            
            fields.put("multipage_background_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_background_color">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_background_color</a>
         */
        public HtmlToPdfClient setPageBackgroundColor(String color) {
            if (!color.matches("^[0-9a-fA-F]{6,8}$"))
                throw new Error(createInvalidValueMessage(color, "setPageBackgroundColor", "html-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            
            fields.put("page_background_color", color);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_use_print_media">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_use_print_media</a>
         */
        public HtmlToPdfClient setUsePrintMedia(boolean value) {
            fields.put("use_print_media", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_background">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_background</a>
         */
        public HtmlToPdfClient setNoBackground(boolean value) {
            fields.put("no_background", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_disable_javascript">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_disable_javascript</a>
         */
        public HtmlToPdfClient setDisableJavascript(boolean value) {
            fields.put("disable_javascript", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_disable_image_loading">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_disable_image_loading</a>
         */
        public HtmlToPdfClient setDisableImageLoading(boolean value) {
            fields.put("disable_image_loading", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_disable_remote_fonts">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_disable_remote_fonts</a>
         */
        public HtmlToPdfClient setDisableRemoteFonts(boolean value) {
            fields.put("disable_remote_fonts", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_use_mobile_user_agent">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_use_mobile_user_agent</a>
         */
        public HtmlToPdfClient setUseMobileUserAgent(boolean value) {
            fields.put("use_mobile_user_agent", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_load_iframes">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_load_iframes</a>
         */
        public HtmlToPdfClient setLoadIframes(String iframes) {
            if (!iframes.matches("(?i)^(all|same-origin|none)$"))
                throw new Error(createInvalidValueMessage(iframes, "setLoadIframes", "html-to-pdf", "Allowed values are all, same-origin, none.", "set_load_iframes"), 470);
            
            fields.put("load_iframes", iframes);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_block_ads">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_block_ads</a>
         */
        public HtmlToPdfClient setBlockAds(boolean value) {
            fields.put("block_ads", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_default_encoding">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_default_encoding</a>
         */
        public HtmlToPdfClient setDefaultEncoding(String encoding) {
            fields.put("default_encoding", encoding);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_locale">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_locale</a>
         */
        public HtmlToPdfClient setLocale(String locale) {
            fields.put("locale", locale);
            return this;
        }


        public HtmlToPdfClient setHttpAuthUserName(String userName) {
            fields.put("http_auth_user_name", userName);
            return this;
        }


        public HtmlToPdfClient setHttpAuthPassword(String password) {
            fields.put("http_auth_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_http_auth">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_http_auth</a>
         */
        public HtmlToPdfClient setHttpAuth(String userName, String password) {
            this.setHttpAuthUserName(userName);
            this.setHttpAuthPassword(password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_cookies">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_cookies</a>
         */
        public HtmlToPdfClient setCookies(String cookies) {
            fields.put("cookies", cookies);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_verify_ssl_certificates">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_verify_ssl_certificates</a>
         */
        public HtmlToPdfClient setVerifySslCertificates(boolean value) {
            fields.put("verify_ssl_certificates", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_fail_on_main_url_error">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_fail_on_main_url_error</a>
         */
        public HtmlToPdfClient setFailOnMainUrlError(boolean failOnError) {
            fields.put("fail_on_main_url_error", failOnError ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_fail_on_any_url_error">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_fail_on_any_url_error</a>
         */
        public HtmlToPdfClient setFailOnAnyUrlError(boolean failOnError) {
            fields.put("fail_on_any_url_error", failOnError ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_xpdfcrowd_header">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_xpdfcrowd_header</a>
         */
        public HtmlToPdfClient setNoXpdfcrowdHeader(boolean value) {
            fields.put("no_xpdfcrowd_header", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_css_page_rule_mode">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_css_page_rule_mode</a>
         */
        public HtmlToPdfClient setCssPageRuleMode(String mode) {
            if (!mode.matches("(?i)^(default|mode1|mode2)$"))
                throw new Error(createInvalidValueMessage(mode, "setCssPageRuleMode", "html-to-pdf", "Allowed values are default, mode1, mode2.", "set_css_page_rule_mode"), 470);
            
            fields.put("css_page_rule_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_custom_css">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_custom_css</a>
         */
        public HtmlToPdfClient setCustomCss(String css) {
            if (!(css != null && !css.isEmpty()))
                throw new Error(createInvalidValueMessage(css, "setCustomCss", "html-to-pdf", "The string must not be empty.", "set_custom_css"), 470);
            
            fields.put("custom_css", css);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_custom_javascript">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_custom_javascript</a>
         */
        public HtmlToPdfClient setCustomJavascript(String javascript) {
            if (!(javascript != null && !javascript.isEmpty()))
                throw new Error(createInvalidValueMessage(javascript, "setCustomJavascript", "html-to-pdf", "The string must not be empty.", "set_custom_javascript"), 470);
            
            fields.put("custom_javascript", javascript);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_on_load_javascript">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_on_load_javascript</a>
         */
        public HtmlToPdfClient setOnLoadJavascript(String javascript) {
            if (!(javascript != null && !javascript.isEmpty()))
                throw new Error(createInvalidValueMessage(javascript, "setOnLoadJavascript", "html-to-pdf", "The string must not be empty.", "set_on_load_javascript"), 470);
            
            fields.put("on_load_javascript", javascript);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_custom_http_header">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_custom_http_header</a>
         */
        public HtmlToPdfClient setCustomHttpHeader(String header) {
            if (!header.matches("^.+:.+$"))
                throw new Error(createInvalidValueMessage(header, "setCustomHttpHeader", "html-to-pdf", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            
            fields.put("custom_http_header", header);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_javascript_delay">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_javascript_delay</a>
         */
        public HtmlToPdfClient setJavascriptDelay(int delay) {
            if (!(delay >= 0))
                throw new Error(createInvalidValueMessage(delay, "setJavascriptDelay", "html-to-pdf", "Must be a positive integer or 0.", "set_javascript_delay"), 470);
            
            fields.put("javascript_delay", Integer.toString(delay));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_element_to_convert">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_element_to_convert</a>
         */
        public HtmlToPdfClient setElementToConvert(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "setElementToConvert", "html-to-pdf", "The string must not be empty.", "set_element_to_convert"), 470);
            
            fields.put("element_to_convert", selectors);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_element_to_convert_mode">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_element_to_convert_mode</a>
         */
        public HtmlToPdfClient setElementToConvertMode(String mode) {
            if (!mode.matches("(?i)^(cut-out|remove-siblings|hide-siblings)$"))
                throw new Error(createInvalidValueMessage(mode, "setElementToConvertMode", "html-to-pdf", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            
            fields.put("element_to_convert_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_wait_for_element">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_wait_for_element</a>
         */
        public HtmlToPdfClient setWaitForElement(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "setWaitForElement", "html-to-pdf", "The string must not be empty.", "set_wait_for_element"), 470);
            
            fields.put("wait_for_element", selectors);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_auto_detect_element_to_convert">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_auto_detect_element_to_convert</a>
         */
        public HtmlToPdfClient setAutoDetectElementToConvert(boolean value) {
            fields.put("auto_detect_element_to_convert", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_readability_enhancements">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_readability_enhancements</a>
         */
        public HtmlToPdfClient setReadabilityEnhancements(String enhancements) {
            if (!enhancements.matches("(?i)^(none|readability-v1|readability-v2|readability-v3|readability-v4)$"))
                throw new Error(createInvalidValueMessage(enhancements, "setReadabilityEnhancements", "html-to-pdf", "Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.", "set_readability_enhancements"), 470);
            
            fields.put("readability_enhancements", enhancements);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_viewport_width">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_viewport_width</a>
         */
        public HtmlToPdfClient setViewportWidth(int width) {
            if (!(width >= 96 && width <= 65000))
                throw new Error(createInvalidValueMessage(width, "setViewportWidth", "html-to-pdf", "The accepted range is 96-65000.", "set_viewport_width"), 470);
            
            fields.put("viewport_width", Integer.toString(width));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_viewport_height">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_viewport_height</a>
         */
        public HtmlToPdfClient setViewportHeight(int height) {
            if (!(height > 0))
                throw new Error(createInvalidValueMessage(height, "setViewportHeight", "html-to-pdf", "Must be a positive integer.", "set_viewport_height"), 470);
            
            fields.put("viewport_height", Integer.toString(height));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_viewport">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_viewport</a>
         */
        public HtmlToPdfClient setViewport(int width, int height) {
            this.setViewportWidth(width);
            this.setViewportHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_rendering_mode">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_rendering_mode</a>
         */
        public HtmlToPdfClient setRenderingMode(String mode) {
            if (!mode.matches("(?i)^(default|viewport)$"))
                throw new Error(createInvalidValueMessage(mode, "setRenderingMode", "html-to-pdf", "Allowed values are default, viewport.", "set_rendering_mode"), 470);
            
            fields.put("rendering_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_smart_scaling_mode">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_smart_scaling_mode</a>
         */
        public HtmlToPdfClient setSmartScalingMode(String mode) {
            if (!mode.matches("(?i)^(default|disabled|viewport-fit|content-fit|single-page-fit|single-page-fit-ex|mode1)$"))
                throw new Error(createInvalidValueMessage(mode, "setSmartScalingMode", "html-to-pdf", "Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit, single-page-fit-ex, mode1.", "set_smart_scaling_mode"), 470);
            
            fields.put("smart_scaling_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_scale_factor">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_scale_factor</a>
         */
        public HtmlToPdfClient setScaleFactor(int factor) {
            if (!(factor >= 10 && factor <= 500))
                throw new Error(createInvalidValueMessage(factor, "setScaleFactor", "html-to-pdf", "The accepted range is 10-500.", "set_scale_factor"), 470);
            
            fields.put("scale_factor", Integer.toString(factor));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_jpeg_quality">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_jpeg_quality</a>
         */
        public HtmlToPdfClient setJpegQuality(int quality) {
            if (!(quality >= 1 && quality <= 100))
                throw new Error(createInvalidValueMessage(quality, "setJpegQuality", "html-to-pdf", "The accepted range is 1-100.", "set_jpeg_quality"), 470);
            
            fields.put("jpeg_quality", Integer.toString(quality));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_convert_images_to_jpeg">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_convert_images_to_jpeg</a>
         */
        public HtmlToPdfClient setConvertImagesToJpeg(String images) {
            if (!images.matches("(?i)^(none|opaque|all)$"))
                throw new Error(createInvalidValueMessage(images, "setConvertImagesToJpeg", "html-to-pdf", "Allowed values are none, opaque, all.", "set_convert_images_to_jpeg"), 470);
            
            fields.put("convert_images_to_jpeg", images);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_image_dpi">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_image_dpi</a>
         */
        public HtmlToPdfClient setImageDpi(int dpi) {
            if (!(dpi >= 0))
                throw new Error(createInvalidValueMessage(dpi, "setImageDpi", "html-to-pdf", "Must be a positive integer or 0.", "set_image_dpi"), 470);
            
            fields.put("image_dpi", Integer.toString(dpi));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_enable_pdf_forms">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_enable_pdf_forms</a>
         */
        public HtmlToPdfClient setEnablePdfForms(boolean value) {
            fields.put("enable_pdf_forms", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_linearize">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_linearize</a>
         */
        public HtmlToPdfClient setLinearize(boolean value) {
            fields.put("linearize", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_encrypt">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_encrypt</a>
         */
        public HtmlToPdfClient setEncrypt(boolean value) {
            fields.put("encrypt", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_user_password">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_user_password</a>
         */
        public HtmlToPdfClient setUserPassword(String password) {
            fields.put("user_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_owner_password">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_owner_password</a>
         */
        public HtmlToPdfClient setOwnerPassword(String password) {
            fields.put("owner_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_print">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_print</a>
         */
        public HtmlToPdfClient setNoPrint(boolean value) {
            fields.put("no_print", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_modify">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_modify</a>
         */
        public HtmlToPdfClient setNoModify(boolean value) {
            fields.put("no_modify", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_copy">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_no_copy</a>
         */
        public HtmlToPdfClient setNoCopy(boolean value) {
            fields.put("no_copy", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_title">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_title</a>
         */
        public HtmlToPdfClient setTitle(String title) {
            fields.put("title", title);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_subject">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_subject</a>
         */
        public HtmlToPdfClient setSubject(String subject) {
            fields.put("subject", subject);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_author">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_author</a>
         */
        public HtmlToPdfClient setAuthor(String author) {
            fields.put("author", author);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_keywords">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_keywords</a>
         */
        public HtmlToPdfClient setKeywords(String keywords) {
            fields.put("keywords", keywords);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_extract_meta_tags">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_extract_meta_tags</a>
         */
        public HtmlToPdfClient setExtractMetaTags(boolean value) {
            fields.put("extract_meta_tags", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_layout">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_layout</a>
         */
        public HtmlToPdfClient setPageLayout(String layout) {
            if (!layout.matches("(?i)^(single-page|one-column|two-column-left|two-column-right)$"))
                throw new Error(createInvalidValueMessage(layout, "setPageLayout", "html-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            
            fields.put("page_layout", layout);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_mode">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_page_mode</a>
         */
        public HtmlToPdfClient setPageMode(String mode) {
            if (!mode.matches("(?i)^(full-screen|thumbnails|outlines)$"))
                throw new Error(createInvalidValueMessage(mode, "setPageMode", "html-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            
            fields.put("page_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_initial_zoom_type">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_initial_zoom_type</a>
         */
        public HtmlToPdfClient setInitialZoomType(String zoomType) {
            if (!zoomType.matches("(?i)^(fit-width|fit-height|fit-page)$"))
                throw new Error(createInvalidValueMessage(zoomType, "setInitialZoomType", "html-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            
            fields.put("initial_zoom_type", zoomType);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_initial_page">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_initial_page</a>
         */
        public HtmlToPdfClient setInitialPage(int page) {
            if (!(page > 0))
                throw new Error(createInvalidValueMessage(page, "setInitialPage", "html-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            
            fields.put("initial_page", Integer.toString(page));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_initial_zoom">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_initial_zoom</a>
         */
        public HtmlToPdfClient setInitialZoom(int zoom) {
            if (!(zoom > 0))
                throw new Error(createInvalidValueMessage(zoom, "setInitialZoom", "html-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            
            fields.put("initial_zoom", Integer.toString(zoom));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_hide_toolbar">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_hide_toolbar</a>
         */
        public HtmlToPdfClient setHideToolbar(boolean value) {
            fields.put("hide_toolbar", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_hide_menubar">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_hide_menubar</a>
         */
        public HtmlToPdfClient setHideMenubar(boolean value) {
            fields.put("hide_menubar", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_hide_window_ui">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_hide_window_ui</a>
         */
        public HtmlToPdfClient setHideWindowUi(boolean value) {
            fields.put("hide_window_ui", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_fit_window">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_fit_window</a>
         */
        public HtmlToPdfClient setFitWindow(boolean value) {
            fields.put("fit_window", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_center_window">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_center_window</a>
         */
        public HtmlToPdfClient setCenterWindow(boolean value) {
            fields.put("center_window", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_display_title">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_display_title</a>
         */
        public HtmlToPdfClient setDisplayTitle(boolean value) {
            fields.put("display_title", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_right_to_left">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_right_to_left</a>
         */
        public HtmlToPdfClient setRightToLeft(boolean value) {
            fields.put("right_to_left", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_string">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_string</a>
         */
        public HtmlToPdfClient setDataString(String dataString) {
            fields.put("data_string", dataString);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_file">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_file</a>
         */
        public HtmlToPdfClient setDataFile(String dataFile) {
            files.put("data_file", dataFile);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_format">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_format</a>
         */
        public HtmlToPdfClient setDataFormat(String dataFormat) {
            if (!dataFormat.matches("(?i)^(auto|json|xml|yaml|csv)$"))
                throw new Error(createInvalidValueMessage(dataFormat, "setDataFormat", "html-to-pdf", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            
            fields.put("data_format", dataFormat);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_encoding">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_encoding</a>
         */
        public HtmlToPdfClient setDataEncoding(String encoding) {
            fields.put("data_encoding", encoding);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_ignore_undefined">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_ignore_undefined</a>
         */
        public HtmlToPdfClient setDataIgnoreUndefined(boolean value) {
            fields.put("data_ignore_undefined", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_auto_escape">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_auto_escape</a>
         */
        public HtmlToPdfClient setDataAutoEscape(boolean value) {
            fields.put("data_auto_escape", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_trim_blocks">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_trim_blocks</a>
         */
        public HtmlToPdfClient setDataTrimBlocks(boolean value) {
            fields.put("data_trim_blocks", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_options">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_data_options</a>
         */
        public HtmlToPdfClient setDataOptions(String options) {
            fields.put("data_options", options);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_debug_log">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_debug_log</a>
         */
        public HtmlToPdfClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_debug_log_url">https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_debug_log_url</a>
         */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_remaining_credit_count">https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_remaining_credit_count</a>
         */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_consumed_credit_count">https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_consumed_credit_count</a>
         */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_job_id">https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_job_id</a>
         */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_page_count">https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_page_count</a>
         */
        public int getPageCount() {
            return helper.getPageCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_total_page_count">https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_total_page_count</a>
         */
        public int getTotalPageCount() {
            return helper.getTotalPageCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_output_size">https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_output_size</a>
         */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_version">https://pdfcrowd.com/api/html-to-pdf-java/ref/#get_version</a>
         */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_tag">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_tag</a>
         */
        public HtmlToPdfClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_http_proxy">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_http_proxy</a>
         */
        public HtmlToPdfClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_https_proxy">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_https_proxy</a>
         */
        public HtmlToPdfClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_client_certificate">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_client_certificate</a>
         */
        public HtmlToPdfClient setClientCertificate(String certificate) {
            if (!(new File(certificate).length() > 0))
                throw new Error(createInvalidValueMessage(certificate, "setClientCertificate", "html-to-pdf", "The file must exist and not be empty.", "set_client_certificate"), 470);
            
            files.put("client_certificate", certificate);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_client_certificate_password">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_client_certificate_password</a>
         */
        public HtmlToPdfClient setClientCertificatePassword(String password) {
            fields.put("client_certificate_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_layout_dpi">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_layout_dpi</a>
         */
        public HtmlToPdfClient setLayoutDpi(int dpi) {
            if (!(dpi >= 72 && dpi <= 600))
                throw new Error(createInvalidValueMessage(dpi, "setLayoutDpi", "html-to-pdf", "The accepted range is 72-600.", "set_layout_dpi"), 470);
            
            fields.put("layout_dpi", Integer.toString(dpi));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area_x">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area_x</a>
         */
        public HtmlToPdfClient setContentAreaX(String x) {
            if (!x.matches("(?i)^0$|^\\-?[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(x, "setContentAreaX", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.", "set_content_area_x"), 470);
            
            fields.put("content_area_x", x);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area_y">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area_y</a>
         */
        public HtmlToPdfClient setContentAreaY(String y) {
            if (!y.matches("(?i)^0$|^\\-?[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(y, "setContentAreaY", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.", "set_content_area_y"), 470);
            
            fields.put("content_area_y", y);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area_width">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area_width</a>
         */
        public HtmlToPdfClient setContentAreaWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setContentAreaWidth", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_content_area_width"), 470);
            
            fields.put("content_area_width", width);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area_height">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area_height</a>
         */
        public HtmlToPdfClient setContentAreaHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setContentAreaHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_content_area_height"), 470);
            
            fields.put("content_area_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_content_area</a>
         */
        public HtmlToPdfClient setContentArea(String x, String y, String width, String height) {
            this.setContentAreaX(x);
            this.setContentAreaY(y);
            this.setContentAreaWidth(width);
            this.setContentAreaHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_contents_matrix">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_contents_matrix</a>
         */
        public HtmlToPdfClient setContentsMatrix(String matrix) {
            fields.put("contents_matrix", matrix);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_matrix">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_matrix</a>
         */
        public HtmlToPdfClient setHeaderMatrix(String matrix) {
            fields.put("header_matrix", matrix);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_footer_matrix">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_footer_matrix</a>
         */
        public HtmlToPdfClient setFooterMatrix(String matrix) {
            fields.put("footer_matrix", matrix);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_disable_page_height_optimization">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_disable_page_height_optimization</a>
         */
        public HtmlToPdfClient setDisablePageHeightOptimization(boolean value) {
            fields.put("disable_page_height_optimization", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_main_document_css_annotation">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_main_document_css_annotation</a>
         */
        public HtmlToPdfClient setMainDocumentCssAnnotation(boolean value) {
            fields.put("main_document_css_annotation", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_footer_css_annotation">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_header_footer_css_annotation</a>
         */
        public HtmlToPdfClient setHeaderFooterCssAnnotation(boolean value) {
            fields.put("header_footer_css_annotation", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_max_loading_time">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_max_loading_time</a>
         */
        public HtmlToPdfClient setMaxLoadingTime(int maxTime) {
            if (!(maxTime >= 10 && maxTime <= 30))
                throw new Error(createInvalidValueMessage(maxTime, "setMaxLoadingTime", "html-to-pdf", "The accepted range is 10-30.", "set_max_loading_time"), 470);
            
            fields.put("max_loading_time", Integer.toString(maxTime));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_conversion_config">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_conversion_config</a>
         */
        public HtmlToPdfClient setConversionConfig(String jsonString) {
            fields.put("conversion_config", jsonString);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_conversion_config_file">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_conversion_config_file</a>
         */
        public HtmlToPdfClient setConversionConfigFile(String filepath) {
            if (!(new File(filepath).length() > 0))
                throw new Error(createInvalidValueMessage(filepath, "setConversionConfigFile", "html-to-pdf", "The file must exist and not be empty.", "set_conversion_config_file"), 470);
            
            files.put("conversion_config_file", filepath);
            return this;
        }


        public HtmlToPdfClient setSubprocessReferrer(String referrer) {
            fields.put("subprocess_referrer", referrer);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_converter_user_agent">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_converter_user_agent</a>
         */
        public HtmlToPdfClient setConverterUserAgent(String agent) {
            fields.put("converter_user_agent", agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_converter_version">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_converter_version</a>
         */
        public HtmlToPdfClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(24.04|20.10|18.10|latest)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "html-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_use_http">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_use_http</a>
         */
        public HtmlToPdfClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_client_user_agent">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_client_user_agent</a>
         */
        public HtmlToPdfClient setClientUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_user_agent">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_user_agent</a>
         */
        public HtmlToPdfClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_proxy">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_proxy</a>
         */
        public HtmlToPdfClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_retry_count">https://pdfcrowd.com/api/html-to-pdf-java/ref/#set_retry_count</a>
         */
        public HtmlToPdfClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

    /**
     * Conversion from HTML to image.
     *
     * @see <a href="https://pdfcrowd.com/api/html-to-image-java/">https://pdfcrowd.com/api/html-to-image-java/</a>
     */
    public static final class HtmlToImageClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#HtmlToImageClient">https://pdfcrowd.com/api/html-to-image-java/ref/#HtmlToImageClient</a>
         */
        public HtmlToImageClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "html");
            fields.put("output_format", "png");
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_output_format">https://pdfcrowd.com/api/html-to-image-java/ref/#set_output_format</a>
         */
        public HtmlToImageClient setOutputFormat(String outputFormat) {
            if (!outputFormat.matches("(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$"))
                throw new Error(createInvalidValueMessage(outputFormat, "setOutputFormat", "html-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            
            fields.put("output_format", outputFormat);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_url">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_url</a>
         */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "html-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_url_to_stream">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_url_to_stream</a>
         */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "html-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_url_to_file">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_url_to_file</a>
         */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertUrlToFile::file_path", "html-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertUrlToStream(url, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_file">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_file</a>
         */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_file_to_stream">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_file_to_stream</a>
         */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_file_to_file">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_file_to_file</a>
         */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertFileToFile::file_path", "html-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertFileToStream(file, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_string">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_string</a>
         */
        public byte[] convertString(String text) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "convertString", "html-to-image", "The string must not be empty.", "convert_string"), 470);
            
            fields.put("text", text);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_string_to_stream">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_string_to_stream</a>
         */
        public void convertStringToStream(String text, OutputStream outStream) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "convertStringToStream::text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470);
            
            fields.put("text", text);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_string_to_file">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_string_to_file</a>
         */
        public void convertStringToFile(String text, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStringToFile::file_path", "html-to-image", "The string must not be empty.", "convert_string_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStringToStream(text, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_stream">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_stream</a>
         */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_stream_to_stream">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_stream_to_stream</a>
         */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#convert_stream_to_file">https://pdfcrowd.com/api/html-to-image-java/ref/#convert_stream_to_file</a>
         */
        public void convertStreamToFile(InputStream inStream, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStreamToFile::file_path", "html-to-image", "The string must not be empty.", "convert_stream_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStreamToStream(inStream, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_zip_main_filename">https://pdfcrowd.com/api/html-to-image-java/ref/#set_zip_main_filename</a>
         */
        public HtmlToImageClient setZipMainFilename(String filename) {
            fields.put("zip_main_filename", filename);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_screenshot_width">https://pdfcrowd.com/api/html-to-image-java/ref/#set_screenshot_width</a>
         */
        public HtmlToImageClient setScreenshotWidth(int width) {
            if (!(width >= 96 && width <= 65000))
                throw new Error(createInvalidValueMessage(width, "setScreenshotWidth", "html-to-image", "The accepted range is 96-65000.", "set_screenshot_width"), 470);
            
            fields.put("screenshot_width", Integer.toString(width));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_screenshot_height">https://pdfcrowd.com/api/html-to-image-java/ref/#set_screenshot_height</a>
         */
        public HtmlToImageClient setScreenshotHeight(int height) {
            if (!(height > 0))
                throw new Error(createInvalidValueMessage(height, "setScreenshotHeight", "html-to-image", "Must be a positive integer.", "set_screenshot_height"), 470);
            
            fields.put("screenshot_height", Integer.toString(height));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_scale_factor">https://pdfcrowd.com/api/html-to-image-java/ref/#set_scale_factor</a>
         */
        public HtmlToImageClient setScaleFactor(int factor) {
            if (!(factor > 0))
                throw new Error(createInvalidValueMessage(factor, "setScaleFactor", "html-to-image", "Must be a positive integer.", "set_scale_factor"), 470);
            
            fields.put("scale_factor", Integer.toString(factor));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_background_color">https://pdfcrowd.com/api/html-to-image-java/ref/#set_background_color</a>
         */
        public HtmlToImageClient setBackgroundColor(String color) {
            if (!color.matches("^[0-9a-fA-F]{6,8}$"))
                throw new Error(createInvalidValueMessage(color, "setBackgroundColor", "html-to-image", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_background_color"), 470);
            
            fields.put("background_color", color);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_use_print_media">https://pdfcrowd.com/api/html-to-image-java/ref/#set_use_print_media</a>
         */
        public HtmlToImageClient setUsePrintMedia(boolean value) {
            fields.put("use_print_media", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_no_background">https://pdfcrowd.com/api/html-to-image-java/ref/#set_no_background</a>
         */
        public HtmlToImageClient setNoBackground(boolean value) {
            fields.put("no_background", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_disable_javascript">https://pdfcrowd.com/api/html-to-image-java/ref/#set_disable_javascript</a>
         */
        public HtmlToImageClient setDisableJavascript(boolean value) {
            fields.put("disable_javascript", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_disable_image_loading">https://pdfcrowd.com/api/html-to-image-java/ref/#set_disable_image_loading</a>
         */
        public HtmlToImageClient setDisableImageLoading(boolean value) {
            fields.put("disable_image_loading", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_disable_remote_fonts">https://pdfcrowd.com/api/html-to-image-java/ref/#set_disable_remote_fonts</a>
         */
        public HtmlToImageClient setDisableRemoteFonts(boolean value) {
            fields.put("disable_remote_fonts", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_use_mobile_user_agent">https://pdfcrowd.com/api/html-to-image-java/ref/#set_use_mobile_user_agent</a>
         */
        public HtmlToImageClient setUseMobileUserAgent(boolean value) {
            fields.put("use_mobile_user_agent", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_load_iframes">https://pdfcrowd.com/api/html-to-image-java/ref/#set_load_iframes</a>
         */
        public HtmlToImageClient setLoadIframes(String iframes) {
            if (!iframes.matches("(?i)^(all|same-origin|none)$"))
                throw new Error(createInvalidValueMessage(iframes, "setLoadIframes", "html-to-image", "Allowed values are all, same-origin, none.", "set_load_iframes"), 470);
            
            fields.put("load_iframes", iframes);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_block_ads">https://pdfcrowd.com/api/html-to-image-java/ref/#set_block_ads</a>
         */
        public HtmlToImageClient setBlockAds(boolean value) {
            fields.put("block_ads", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_default_encoding">https://pdfcrowd.com/api/html-to-image-java/ref/#set_default_encoding</a>
         */
        public HtmlToImageClient setDefaultEncoding(String encoding) {
            fields.put("default_encoding", encoding);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_locale">https://pdfcrowd.com/api/html-to-image-java/ref/#set_locale</a>
         */
        public HtmlToImageClient setLocale(String locale) {
            fields.put("locale", locale);
            return this;
        }


        public HtmlToImageClient setHttpAuthUserName(String userName) {
            fields.put("http_auth_user_name", userName);
            return this;
        }


        public HtmlToImageClient setHttpAuthPassword(String password) {
            fields.put("http_auth_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_http_auth">https://pdfcrowd.com/api/html-to-image-java/ref/#set_http_auth</a>
         */
        public HtmlToImageClient setHttpAuth(String userName, String password) {
            this.setHttpAuthUserName(userName);
            this.setHttpAuthPassword(password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_cookies">https://pdfcrowd.com/api/html-to-image-java/ref/#set_cookies</a>
         */
        public HtmlToImageClient setCookies(String cookies) {
            fields.put("cookies", cookies);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_verify_ssl_certificates">https://pdfcrowd.com/api/html-to-image-java/ref/#set_verify_ssl_certificates</a>
         */
        public HtmlToImageClient setVerifySslCertificates(boolean value) {
            fields.put("verify_ssl_certificates", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_fail_on_main_url_error">https://pdfcrowd.com/api/html-to-image-java/ref/#set_fail_on_main_url_error</a>
         */
        public HtmlToImageClient setFailOnMainUrlError(boolean failOnError) {
            fields.put("fail_on_main_url_error", failOnError ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_fail_on_any_url_error">https://pdfcrowd.com/api/html-to-image-java/ref/#set_fail_on_any_url_error</a>
         */
        public HtmlToImageClient setFailOnAnyUrlError(boolean failOnError) {
            fields.put("fail_on_any_url_error", failOnError ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_no_xpdfcrowd_header">https://pdfcrowd.com/api/html-to-image-java/ref/#set_no_xpdfcrowd_header</a>
         */
        public HtmlToImageClient setNoXpdfcrowdHeader(boolean value) {
            fields.put("no_xpdfcrowd_header", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_custom_css">https://pdfcrowd.com/api/html-to-image-java/ref/#set_custom_css</a>
         */
        public HtmlToImageClient setCustomCss(String css) {
            if (!(css != null && !css.isEmpty()))
                throw new Error(createInvalidValueMessage(css, "setCustomCss", "html-to-image", "The string must not be empty.", "set_custom_css"), 470);
            
            fields.put("custom_css", css);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_custom_javascript">https://pdfcrowd.com/api/html-to-image-java/ref/#set_custom_javascript</a>
         */
        public HtmlToImageClient setCustomJavascript(String javascript) {
            if (!(javascript != null && !javascript.isEmpty()))
                throw new Error(createInvalidValueMessage(javascript, "setCustomJavascript", "html-to-image", "The string must not be empty.", "set_custom_javascript"), 470);
            
            fields.put("custom_javascript", javascript);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_on_load_javascript">https://pdfcrowd.com/api/html-to-image-java/ref/#set_on_load_javascript</a>
         */
        public HtmlToImageClient setOnLoadJavascript(String javascript) {
            if (!(javascript != null && !javascript.isEmpty()))
                throw new Error(createInvalidValueMessage(javascript, "setOnLoadJavascript", "html-to-image", "The string must not be empty.", "set_on_load_javascript"), 470);
            
            fields.put("on_load_javascript", javascript);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_custom_http_header">https://pdfcrowd.com/api/html-to-image-java/ref/#set_custom_http_header</a>
         */
        public HtmlToImageClient setCustomHttpHeader(String header) {
            if (!header.matches("^.+:.+$"))
                throw new Error(createInvalidValueMessage(header, "setCustomHttpHeader", "html-to-image", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            
            fields.put("custom_http_header", header);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_javascript_delay">https://pdfcrowd.com/api/html-to-image-java/ref/#set_javascript_delay</a>
         */
        public HtmlToImageClient setJavascriptDelay(int delay) {
            if (!(delay >= 0))
                throw new Error(createInvalidValueMessage(delay, "setJavascriptDelay", "html-to-image", "Must be a positive integer or 0.", "set_javascript_delay"), 470);
            
            fields.put("javascript_delay", Integer.toString(delay));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_element_to_convert">https://pdfcrowd.com/api/html-to-image-java/ref/#set_element_to_convert</a>
         */
        public HtmlToImageClient setElementToConvert(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "setElementToConvert", "html-to-image", "The string must not be empty.", "set_element_to_convert"), 470);
            
            fields.put("element_to_convert", selectors);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_element_to_convert_mode">https://pdfcrowd.com/api/html-to-image-java/ref/#set_element_to_convert_mode</a>
         */
        public HtmlToImageClient setElementToConvertMode(String mode) {
            if (!mode.matches("(?i)^(cut-out|remove-siblings|hide-siblings)$"))
                throw new Error(createInvalidValueMessage(mode, "setElementToConvertMode", "html-to-image", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            
            fields.put("element_to_convert_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_wait_for_element">https://pdfcrowd.com/api/html-to-image-java/ref/#set_wait_for_element</a>
         */
        public HtmlToImageClient setWaitForElement(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "setWaitForElement", "html-to-image", "The string must not be empty.", "set_wait_for_element"), 470);
            
            fields.put("wait_for_element", selectors);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_auto_detect_element_to_convert">https://pdfcrowd.com/api/html-to-image-java/ref/#set_auto_detect_element_to_convert</a>
         */
        public HtmlToImageClient setAutoDetectElementToConvert(boolean value) {
            fields.put("auto_detect_element_to_convert", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_readability_enhancements">https://pdfcrowd.com/api/html-to-image-java/ref/#set_readability_enhancements</a>
         */
        public HtmlToImageClient setReadabilityEnhancements(String enhancements) {
            if (!enhancements.matches("(?i)^(none|readability-v1|readability-v2|readability-v3|readability-v4)$"))
                throw new Error(createInvalidValueMessage(enhancements, "setReadabilityEnhancements", "html-to-image", "Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.", "set_readability_enhancements"), 470);
            
            fields.put("readability_enhancements", enhancements);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_string">https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_string</a>
         */
        public HtmlToImageClient setDataString(String dataString) {
            fields.put("data_string", dataString);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_file">https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_file</a>
         */
        public HtmlToImageClient setDataFile(String dataFile) {
            files.put("data_file", dataFile);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_format">https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_format</a>
         */
        public HtmlToImageClient setDataFormat(String dataFormat) {
            if (!dataFormat.matches("(?i)^(auto|json|xml|yaml|csv)$"))
                throw new Error(createInvalidValueMessage(dataFormat, "setDataFormat", "html-to-image", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            
            fields.put("data_format", dataFormat);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_encoding">https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_encoding</a>
         */
        public HtmlToImageClient setDataEncoding(String encoding) {
            fields.put("data_encoding", encoding);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_ignore_undefined">https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_ignore_undefined</a>
         */
        public HtmlToImageClient setDataIgnoreUndefined(boolean value) {
            fields.put("data_ignore_undefined", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_auto_escape">https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_auto_escape</a>
         */
        public HtmlToImageClient setDataAutoEscape(boolean value) {
            fields.put("data_auto_escape", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_trim_blocks">https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_trim_blocks</a>
         */
        public HtmlToImageClient setDataTrimBlocks(boolean value) {
            fields.put("data_trim_blocks", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_options">https://pdfcrowd.com/api/html-to-image-java/ref/#set_data_options</a>
         */
        public HtmlToImageClient setDataOptions(String options) {
            fields.put("data_options", options);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_debug_log">https://pdfcrowd.com/api/html-to-image-java/ref/#set_debug_log</a>
         */
        public HtmlToImageClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#get_debug_log_url">https://pdfcrowd.com/api/html-to-image-java/ref/#get_debug_log_url</a>
         */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#get_remaining_credit_count">https://pdfcrowd.com/api/html-to-image-java/ref/#get_remaining_credit_count</a>
         */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#get_consumed_credit_count">https://pdfcrowd.com/api/html-to-image-java/ref/#get_consumed_credit_count</a>
         */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#get_job_id">https://pdfcrowd.com/api/html-to-image-java/ref/#get_job_id</a>
         */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#get_output_size">https://pdfcrowd.com/api/html-to-image-java/ref/#get_output_size</a>
         */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#get_version">https://pdfcrowd.com/api/html-to-image-java/ref/#get_version</a>
         */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_tag">https://pdfcrowd.com/api/html-to-image-java/ref/#set_tag</a>
         */
        public HtmlToImageClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_http_proxy">https://pdfcrowd.com/api/html-to-image-java/ref/#set_http_proxy</a>
         */
        public HtmlToImageClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_https_proxy">https://pdfcrowd.com/api/html-to-image-java/ref/#set_https_proxy</a>
         */
        public HtmlToImageClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_client_certificate">https://pdfcrowd.com/api/html-to-image-java/ref/#set_client_certificate</a>
         */
        public HtmlToImageClient setClientCertificate(String certificate) {
            if (!(new File(certificate).length() > 0))
                throw new Error(createInvalidValueMessage(certificate, "setClientCertificate", "html-to-image", "The file must exist and not be empty.", "set_client_certificate"), 470);
            
            files.put("client_certificate", certificate);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_client_certificate_password">https://pdfcrowd.com/api/html-to-image-java/ref/#set_client_certificate_password</a>
         */
        public HtmlToImageClient setClientCertificatePassword(String password) {
            fields.put("client_certificate_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_max_loading_time">https://pdfcrowd.com/api/html-to-image-java/ref/#set_max_loading_time</a>
         */
        public HtmlToImageClient setMaxLoadingTime(int maxTime) {
            if (!(maxTime >= 10 && maxTime <= 30))
                throw new Error(createInvalidValueMessage(maxTime, "setMaxLoadingTime", "html-to-image", "The accepted range is 10-30.", "set_max_loading_time"), 470);
            
            fields.put("max_loading_time", Integer.toString(maxTime));
            return this;
        }


        public HtmlToImageClient setSubprocessReferrer(String referrer) {
            fields.put("subprocess_referrer", referrer);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_converter_user_agent">https://pdfcrowd.com/api/html-to-image-java/ref/#set_converter_user_agent</a>
         */
        public HtmlToImageClient setConverterUserAgent(String agent) {
            fields.put("converter_user_agent", agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_converter_version">https://pdfcrowd.com/api/html-to-image-java/ref/#set_converter_version</a>
         */
        public HtmlToImageClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(24.04|20.10|18.10|latest)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "html-to-image", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_use_http">https://pdfcrowd.com/api/html-to-image-java/ref/#set_use_http</a>
         */
        public HtmlToImageClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_client_user_agent">https://pdfcrowd.com/api/html-to-image-java/ref/#set_client_user_agent</a>
         */
        public HtmlToImageClient setClientUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_user_agent">https://pdfcrowd.com/api/html-to-image-java/ref/#set_user_agent</a>
         */
        public HtmlToImageClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_proxy">https://pdfcrowd.com/api/html-to-image-java/ref/#set_proxy</a>
         */
        public HtmlToImageClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/html-to-image-java/ref/#set_retry_count">https://pdfcrowd.com/api/html-to-image-java/ref/#set_retry_count</a>
         */
        public HtmlToImageClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

    /**
     * Conversion from one image format to another image format.
     *
     * @see <a href="https://pdfcrowd.com/api/image-to-image-java/">https://pdfcrowd.com/api/image-to-image-java/</a>
     */
    public static final class ImageToImageClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#ImageToImageClient">https://pdfcrowd.com/api/image-to-image-java/ref/#ImageToImageClient</a>
         */
        public ImageToImageClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "image");
            fields.put("output_format", "png");
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_url">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_url</a>
         */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "image-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_url_to_stream">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_url_to_stream</a>
         */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "image-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_url_to_file">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_url_to_file</a>
         */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertUrlToFile::file_path", "image-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertUrlToStream(url, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_file">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_file</a>
         */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_file_to_stream">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_file_to_stream</a>
         */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_file_to_file">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_file_to_file</a>
         */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertFileToFile::file_path", "image-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertFileToStream(file, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_raw_data">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_raw_data</a>
         */
        public byte[] convertRawData(byte[] data) {
            rawData.put("file", data);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_raw_data_to_stream">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_raw_data_to_stream</a>
         */
        public void convertRawDataToStream(byte[] data, OutputStream outStream) {
            rawData.put("file", data);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_raw_data_to_file">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_raw_data_to_file</a>
         */
        public void convertRawDataToFile(byte[] data, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertRawDataToFile::file_path", "image-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertRawDataToStream(data, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_stream">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_stream</a>
         */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_stream_to_stream">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_stream_to_stream</a>
         */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#convert_stream_to_file">https://pdfcrowd.com/api/image-to-image-java/ref/#convert_stream_to_file</a>
         */
        public void convertStreamToFile(InputStream inStream, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStreamToFile::file_path", "image-to-image", "The string must not be empty.", "convert_stream_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStreamToStream(inStream, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_output_format">https://pdfcrowd.com/api/image-to-image-java/ref/#set_output_format</a>
         */
        public ImageToImageClient setOutputFormat(String outputFormat) {
            if (!outputFormat.matches("(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$"))
                throw new Error(createInvalidValueMessage(outputFormat, "setOutputFormat", "image-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            
            fields.put("output_format", outputFormat);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_resize">https://pdfcrowd.com/api/image-to-image-java/ref/#set_resize</a>
         */
        public ImageToImageClient setResize(String resize) {
            fields.put("resize", resize);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_rotate">https://pdfcrowd.com/api/image-to-image-java/ref/#set_rotate</a>
         */
        public ImageToImageClient setRotate(String rotate) {
            fields.put("rotate", rotate);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area_x">https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area_x</a>
         */
        public ImageToImageClient setCropAreaX(String x) {
            if (!x.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(x, "setCropAreaX", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_x"), 470);
            
            fields.put("crop_area_x", x);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area_y">https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area_y</a>
         */
        public ImageToImageClient setCropAreaY(String y) {
            if (!y.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(y, "setCropAreaY", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_y"), 470);
            
            fields.put("crop_area_y", y);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area_width">https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area_width</a>
         */
        public ImageToImageClient setCropAreaWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setCropAreaWidth", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_width"), 470);
            
            fields.put("crop_area_width", width);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area_height">https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area_height</a>
         */
        public ImageToImageClient setCropAreaHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setCropAreaHeight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_height"), 470);
            
            fields.put("crop_area_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area">https://pdfcrowd.com/api/image-to-image-java/ref/#set_crop_area</a>
         */
        public ImageToImageClient setCropArea(String x, String y, String width, String height) {
            this.setCropAreaX(x);
            this.setCropAreaY(y);
            this.setCropAreaWidth(width);
            this.setCropAreaHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_remove_borders">https://pdfcrowd.com/api/image-to-image-java/ref/#set_remove_borders</a>
         */
        public ImageToImageClient setRemoveBorders(boolean value) {
            fields.put("remove_borders", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_size">https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_size</a>
         */
        public ImageToImageClient setCanvasSize(String size) {
            if (!size.matches("(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$"))
                throw new Error(createInvalidValueMessage(size, "setCanvasSize", "image-to-image", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_canvas_size"), 470);
            
            fields.put("canvas_size", size);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_width">https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_width</a>
         */
        public ImageToImageClient setCanvasWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setCanvasWidth", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_canvas_width"), 470);
            
            fields.put("canvas_width", width);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_height">https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_height</a>
         */
        public ImageToImageClient setCanvasHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setCanvasHeight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_canvas_height"), 470);
            
            fields.put("canvas_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_dimensions">https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_dimensions</a>
         */
        public ImageToImageClient setCanvasDimensions(String width, String height) {
            this.setCanvasWidth(width);
            this.setCanvasHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_orientation">https://pdfcrowd.com/api/image-to-image-java/ref/#set_orientation</a>
         */
        public ImageToImageClient setOrientation(String orientation) {
            if (!orientation.matches("(?i)^(landscape|portrait)$"))
                throw new Error(createInvalidValueMessage(orientation, "setOrientation", "image-to-image", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            
            fields.put("orientation", orientation);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_position">https://pdfcrowd.com/api/image-to-image-java/ref/#set_position</a>
         */
        public ImageToImageClient setPosition(String position) {
            if (!position.matches("(?i)^(center|top|bottom|left|right|top-left|top-right|bottom-left|bottom-right)$"))
                throw new Error(createInvalidValueMessage(position, "setPosition", "image-to-image", "Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.", "set_position"), 470);
            
            fields.put("position", position);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_print_canvas_mode">https://pdfcrowd.com/api/image-to-image-java/ref/#set_print_canvas_mode</a>
         */
        public ImageToImageClient setPrintCanvasMode(String mode) {
            if (!mode.matches("(?i)^(default|fit|stretch)$"))
                throw new Error(createInvalidValueMessage(mode, "setPrintCanvasMode", "image-to-image", "Allowed values are default, fit, stretch.", "set_print_canvas_mode"), 470);
            
            fields.put("print_canvas_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_margin_top">https://pdfcrowd.com/api/image-to-image-java/ref/#set_margin_top</a>
         */
        public ImageToImageClient setMarginTop(String top) {
            if (!top.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(top, "setMarginTop", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            
            fields.put("margin_top", top);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_margin_right">https://pdfcrowd.com/api/image-to-image-java/ref/#set_margin_right</a>
         */
        public ImageToImageClient setMarginRight(String right) {
            if (!right.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(right, "setMarginRight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            
            fields.put("margin_right", right);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_margin_bottom">https://pdfcrowd.com/api/image-to-image-java/ref/#set_margin_bottom</a>
         */
        public ImageToImageClient setMarginBottom(String bottom) {
            if (!bottom.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(bottom, "setMarginBottom", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            
            fields.put("margin_bottom", bottom);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_margin_left">https://pdfcrowd.com/api/image-to-image-java/ref/#set_margin_left</a>
         */
        public ImageToImageClient setMarginLeft(String left) {
            if (!left.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(left, "setMarginLeft", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            
            fields.put("margin_left", left);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_margins">https://pdfcrowd.com/api/image-to-image-java/ref/#set_margins</a>
         */
        public ImageToImageClient setMargins(String top, String right, String bottom, String left) {
            this.setMarginTop(top);
            this.setMarginRight(right);
            this.setMarginBottom(bottom);
            this.setMarginLeft(left);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_background_color">https://pdfcrowd.com/api/image-to-image-java/ref/#set_canvas_background_color</a>
         */
        public ImageToImageClient setCanvasBackgroundColor(String color) {
            if (!color.matches("^[0-9a-fA-F]{6,8}$"))
                throw new Error(createInvalidValueMessage(color, "setCanvasBackgroundColor", "image-to-image", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_canvas_background_color"), 470);
            
            fields.put("canvas_background_color", color);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_dpi">https://pdfcrowd.com/api/image-to-image-java/ref/#set_dpi</a>
         */
        public ImageToImageClient setDpi(int dpi) {
            fields.put("dpi", Integer.toString(dpi));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_debug_log">https://pdfcrowd.com/api/image-to-image-java/ref/#set_debug_log</a>
         */
        public ImageToImageClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#get_debug_log_url">https://pdfcrowd.com/api/image-to-image-java/ref/#get_debug_log_url</a>
         */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#get_remaining_credit_count">https://pdfcrowd.com/api/image-to-image-java/ref/#get_remaining_credit_count</a>
         */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#get_consumed_credit_count">https://pdfcrowd.com/api/image-to-image-java/ref/#get_consumed_credit_count</a>
         */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#get_job_id">https://pdfcrowd.com/api/image-to-image-java/ref/#get_job_id</a>
         */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#get_output_size">https://pdfcrowd.com/api/image-to-image-java/ref/#get_output_size</a>
         */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#get_version">https://pdfcrowd.com/api/image-to-image-java/ref/#get_version</a>
         */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_tag">https://pdfcrowd.com/api/image-to-image-java/ref/#set_tag</a>
         */
        public ImageToImageClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_http_proxy">https://pdfcrowd.com/api/image-to-image-java/ref/#set_http_proxy</a>
         */
        public ImageToImageClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_https_proxy">https://pdfcrowd.com/api/image-to-image-java/ref/#set_https_proxy</a>
         */
        public ImageToImageClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_converter_version">https://pdfcrowd.com/api/image-to-image-java/ref/#set_converter_version</a>
         */
        public ImageToImageClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(24.04|20.10|18.10|latest)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "image-to-image", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_use_http">https://pdfcrowd.com/api/image-to-image-java/ref/#set_use_http</a>
         */
        public ImageToImageClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_client_user_agent">https://pdfcrowd.com/api/image-to-image-java/ref/#set_client_user_agent</a>
         */
        public ImageToImageClient setClientUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_user_agent">https://pdfcrowd.com/api/image-to-image-java/ref/#set_user_agent</a>
         */
        public ImageToImageClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_proxy">https://pdfcrowd.com/api/image-to-image-java/ref/#set_proxy</a>
         */
        public ImageToImageClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-image-java/ref/#set_retry_count">https://pdfcrowd.com/api/image-to-image-java/ref/#set_retry_count</a>
         */
        public ImageToImageClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

    /**
     * Conversion from PDF to PDF.
     *
     * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/">https://pdfcrowd.com/api/pdf-to-pdf-java/</a>
     */
    public static final class PdfToPdfClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#PdfToPdfClient">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#PdfToPdfClient</a>
         */
        public PdfToPdfClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "pdf");
            fields.put("output_format", "pdf");
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_action">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_action</a>
         */
        public PdfToPdfClient setAction(String action) {
            if (!action.matches("(?i)^(join|shuffle|extract|delete)$"))
                throw new Error(createInvalidValueMessage(action, "setAction", "pdf-to-pdf", "Allowed values are join, shuffle, extract, delete.", "set_action"), 470);
            
            fields.put("action", action);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#convert">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#convert</a>
         */
        public byte[] convert() {
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#convert_to_stream">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#convert_to_stream</a>
         */
        public void convertToStream(OutputStream outStream) {
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#convert_to_file">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#convert_to_file</a>
         */
        public void convertToFile(String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertToFile", "pdf-to-pdf", "The string must not be empty.", "convert_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertToStream(outputFile);
            outputFile.close();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#add_pdf_file">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#add_pdf_file</a>
         */
        public PdfToPdfClient addPdfFile(String filePath) {
            if (!(new File(filePath).length() > 0))
                throw new Error(createInvalidValueMessage(filePath, "addPdfFile", "pdf-to-pdf", "The file must exist and not be empty.", "add_pdf_file"), 470);
            
            files.put("f_" + Integer.toString(fileId), filePath);
            fileId++;
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#add_pdf_raw_data">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#add_pdf_raw_data</a>
         */
        public PdfToPdfClient addPdfRawData(byte[] data) {
            if (!(data != null && data.length > 300 && (new String(data, 0, 4).equals("%PDF"))))
                throw new Error(createInvalidValueMessage("raw PDF data", "addPdfRawData", "pdf-to-pdf", "The input data must be PDF content.", "add_pdf_raw_data"), 470);
            
            rawData.put("f_" + Integer.toString(fileId), data);
            fileId++;
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_input_pdf_password">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_input_pdf_password</a>
         */
        public PdfToPdfClient setInputPdfPassword(String password) {
            fields.put("input_pdf_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_range">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_range</a>
         */
        public PdfToPdfClient setPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPageRange", "pdf-to-pdf", "A comma separated list of page numbers or ranges.", "set_page_range"), 470);
            
            fields.put("page_range", pages);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_watermark">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_watermark</a>
         */
        public PdfToPdfClient setPageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setPageWatermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            
            files.put("page_watermark", watermark);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_watermark_url">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_watermark_url</a>
         */
        public PdfToPdfClient setPageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageWatermarkUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            
            fields.put("page_watermark_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_multipage_watermark">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_multipage_watermark</a>
         */
        public PdfToPdfClient setMultipageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setMultipageWatermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            
            files.put("multipage_watermark", watermark);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_multipage_watermark_url">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_multipage_watermark_url</a>
         */
        public PdfToPdfClient setMultipageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageWatermarkUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            
            fields.put("multipage_watermark_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_background">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_background</a>
         */
        public PdfToPdfClient setPageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setPageBackground", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            
            files.put("page_background", background);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_background_url">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_background_url</a>
         */
        public PdfToPdfClient setPageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageBackgroundUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            
            fields.put("page_background_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_multipage_background">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_multipage_background</a>
         */
        public PdfToPdfClient setMultipageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setMultipageBackground", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            
            files.put("multipage_background", background);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_multipage_background_url">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_multipage_background_url</a>
         */
        public PdfToPdfClient setMultipageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageBackgroundUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            
            fields.put("multipage_background_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_linearize">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_linearize</a>
         */
        public PdfToPdfClient setLinearize(boolean value) {
            fields.put("linearize", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_encrypt">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_encrypt</a>
         */
        public PdfToPdfClient setEncrypt(boolean value) {
            fields.put("encrypt", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_user_password">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_user_password</a>
         */
        public PdfToPdfClient setUserPassword(String password) {
            fields.put("user_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_owner_password">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_owner_password</a>
         */
        public PdfToPdfClient setOwnerPassword(String password) {
            fields.put("owner_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_no_print">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_no_print</a>
         */
        public PdfToPdfClient setNoPrint(boolean value) {
            fields.put("no_print", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_no_modify">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_no_modify</a>
         */
        public PdfToPdfClient setNoModify(boolean value) {
            fields.put("no_modify", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_no_copy">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_no_copy</a>
         */
        public PdfToPdfClient setNoCopy(boolean value) {
            fields.put("no_copy", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_title">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_title</a>
         */
        public PdfToPdfClient setTitle(String title) {
            fields.put("title", title);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_subject">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_subject</a>
         */
        public PdfToPdfClient setSubject(String subject) {
            fields.put("subject", subject);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_author">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_author</a>
         */
        public PdfToPdfClient setAuthor(String author) {
            fields.put("author", author);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_keywords">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_keywords</a>
         */
        public PdfToPdfClient setKeywords(String keywords) {
            fields.put("keywords", keywords);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_use_metadata_from">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_use_metadata_from</a>
         */
        public PdfToPdfClient setUseMetadataFrom(int index) {
            if (!(index >= 0))
                throw new Error(createInvalidValueMessage(index, "setUseMetadataFrom", "pdf-to-pdf", "Must be a positive integer or 0.", "set_use_metadata_from"), 470);
            
            fields.put("use_metadata_from", Integer.toString(index));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_layout">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_layout</a>
         */
        public PdfToPdfClient setPageLayout(String layout) {
            if (!layout.matches("(?i)^(single-page|one-column|two-column-left|two-column-right)$"))
                throw new Error(createInvalidValueMessage(layout, "setPageLayout", "pdf-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            
            fields.put("page_layout", layout);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_mode">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_page_mode</a>
         */
        public PdfToPdfClient setPageMode(String mode) {
            if (!mode.matches("(?i)^(full-screen|thumbnails|outlines)$"))
                throw new Error(createInvalidValueMessage(mode, "setPageMode", "pdf-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            
            fields.put("page_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_initial_zoom_type">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_initial_zoom_type</a>
         */
        public PdfToPdfClient setInitialZoomType(String zoomType) {
            if (!zoomType.matches("(?i)^(fit-width|fit-height|fit-page)$"))
                throw new Error(createInvalidValueMessage(zoomType, "setInitialZoomType", "pdf-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            
            fields.put("initial_zoom_type", zoomType);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_initial_page">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_initial_page</a>
         */
        public PdfToPdfClient setInitialPage(int page) {
            if (!(page > 0))
                throw new Error(createInvalidValueMessage(page, "setInitialPage", "pdf-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            
            fields.put("initial_page", Integer.toString(page));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_initial_zoom">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_initial_zoom</a>
         */
        public PdfToPdfClient setInitialZoom(int zoom) {
            if (!(zoom > 0))
                throw new Error(createInvalidValueMessage(zoom, "setInitialZoom", "pdf-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            
            fields.put("initial_zoom", Integer.toString(zoom));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_hide_toolbar">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_hide_toolbar</a>
         */
        public PdfToPdfClient setHideToolbar(boolean value) {
            fields.put("hide_toolbar", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_hide_menubar">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_hide_menubar</a>
         */
        public PdfToPdfClient setHideMenubar(boolean value) {
            fields.put("hide_menubar", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_hide_window_ui">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_hide_window_ui</a>
         */
        public PdfToPdfClient setHideWindowUi(boolean value) {
            fields.put("hide_window_ui", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_fit_window">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_fit_window</a>
         */
        public PdfToPdfClient setFitWindow(boolean value) {
            fields.put("fit_window", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_center_window">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_center_window</a>
         */
        public PdfToPdfClient setCenterWindow(boolean value) {
            fields.put("center_window", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_display_title">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_display_title</a>
         */
        public PdfToPdfClient setDisplayTitle(boolean value) {
            fields.put("display_title", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_right_to_left">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_right_to_left</a>
         */
        public PdfToPdfClient setRightToLeft(boolean value) {
            fields.put("right_to_left", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_debug_log">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_debug_log</a>
         */
        public PdfToPdfClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_debug_log_url">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_debug_log_url</a>
         */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_remaining_credit_count">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_remaining_credit_count</a>
         */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_consumed_credit_count">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_consumed_credit_count</a>
         */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_job_id">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_job_id</a>
         */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_page_count">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_page_count</a>
         */
        public int getPageCount() {
            return helper.getPageCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_output_size">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_output_size</a>
         */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_version">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#get_version</a>
         */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_tag">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_tag</a>
         */
        public PdfToPdfClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_converter_version">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_converter_version</a>
         */
        public PdfToPdfClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(24.04|20.10|18.10|latest)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "pdf-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_use_http">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_use_http</a>
         */
        public PdfToPdfClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_client_user_agent">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_client_user_agent</a>
         */
        public PdfToPdfClient setClientUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_user_agent">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_user_agent</a>
         */
        public PdfToPdfClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_proxy">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_proxy</a>
         */
        public PdfToPdfClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_retry_count">https://pdfcrowd.com/api/pdf-to-pdf-java/ref/#set_retry_count</a>
         */
        public PdfToPdfClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

    /**
     * Conversion from an image to PDF.
     *
     * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/">https://pdfcrowd.com/api/image-to-pdf-java/</a>
     */
    public static final class ImageToPdfClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#ImageToPdfClient">https://pdfcrowd.com/api/image-to-pdf-java/ref/#ImageToPdfClient</a>
         */
        public ImageToPdfClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "image");
            fields.put("output_format", "pdf");
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_url">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_url</a>
         */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_url_to_stream">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_url_to_stream</a>
         */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_url_to_file">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_url_to_file</a>
         */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertUrlToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertUrlToStream(url, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_file">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_file</a>
         */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_file_to_stream">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_file_to_stream</a>
         */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_file_to_file">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_file_to_file</a>
         */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertFileToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertFileToStream(file, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_raw_data">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_raw_data</a>
         */
        public byte[] convertRawData(byte[] data) {
            rawData.put("file", data);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_raw_data_to_stream">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_raw_data_to_stream</a>
         */
        public void convertRawDataToStream(byte[] data, OutputStream outStream) {
            rawData.put("file", data);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_raw_data_to_file">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_raw_data_to_file</a>
         */
        public void convertRawDataToFile(byte[] data, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertRawDataToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertRawDataToStream(data, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_stream">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_stream</a>
         */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_stream_to_stream">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_stream_to_stream</a>
         */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_stream_to_file">https://pdfcrowd.com/api/image-to-pdf-java/ref/#convert_stream_to_file</a>
         */
        public void convertStreamToFile(InputStream inStream, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStreamToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_stream_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStreamToStream(inStream, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_resize">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_resize</a>
         */
        public ImageToPdfClient setResize(String resize) {
            fields.put("resize", resize);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_rotate">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_rotate</a>
         */
        public ImageToPdfClient setRotate(String rotate) {
            fields.put("rotate", rotate);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area_x">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area_x</a>
         */
        public ImageToPdfClient setCropAreaX(String x) {
            if (!x.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(x, "setCropAreaX", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_x"), 470);
            
            fields.put("crop_area_x", x);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area_y">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area_y</a>
         */
        public ImageToPdfClient setCropAreaY(String y) {
            if (!y.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(y, "setCropAreaY", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_y"), 470);
            
            fields.put("crop_area_y", y);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area_width">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area_width</a>
         */
        public ImageToPdfClient setCropAreaWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setCropAreaWidth", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_width"), 470);
            
            fields.put("crop_area_width", width);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area_height">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area_height</a>
         */
        public ImageToPdfClient setCropAreaHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setCropAreaHeight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_height"), 470);
            
            fields.put("crop_area_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_crop_area</a>
         */
        public ImageToPdfClient setCropArea(String x, String y, String width, String height) {
            this.setCropAreaX(x);
            this.setCropAreaY(y);
            this.setCropAreaWidth(width);
            this.setCropAreaHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_remove_borders">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_remove_borders</a>
         */
        public ImageToPdfClient setRemoveBorders(boolean value) {
            fields.put("remove_borders", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_size">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_size</a>
         */
        public ImageToPdfClient setPageSize(String size) {
            if (!size.matches("(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$"))
                throw new Error(createInvalidValueMessage(size, "setPageSize", "image-to-pdf", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            
            fields.put("page_size", size);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_width">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_width</a>
         */
        public ImageToPdfClient setPageWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setPageWidth", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_width"), 470);
            
            fields.put("page_width", width);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_height">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_height</a>
         */
        public ImageToPdfClient setPageHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setPageHeight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_height"), 470);
            
            fields.put("page_height", height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_dimensions">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_dimensions</a>
         */
        public ImageToPdfClient setPageDimensions(String width, String height) {
            this.setPageWidth(width);
            this.setPageHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_orientation">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_orientation</a>
         */
        public ImageToPdfClient setOrientation(String orientation) {
            if (!orientation.matches("(?i)^(landscape|portrait)$"))
                throw new Error(createInvalidValueMessage(orientation, "setOrientation", "image-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            
            fields.put("orientation", orientation);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_position">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_position</a>
         */
        public ImageToPdfClient setPosition(String position) {
            if (!position.matches("(?i)^(center|top|bottom|left|right|top-left|top-right|bottom-left|bottom-right)$"))
                throw new Error(createInvalidValueMessage(position, "setPosition", "image-to-pdf", "Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.", "set_position"), 470);
            
            fields.put("position", position);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_print_page_mode">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_print_page_mode</a>
         */
        public ImageToPdfClient setPrintPageMode(String mode) {
            if (!mode.matches("(?i)^(default|fit|stretch)$"))
                throw new Error(createInvalidValueMessage(mode, "setPrintPageMode", "image-to-pdf", "Allowed values are default, fit, stretch.", "set_print_page_mode"), 470);
            
            fields.put("print_page_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_margin_top">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_margin_top</a>
         */
        public ImageToPdfClient setMarginTop(String top) {
            if (!top.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(top, "setMarginTop", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            
            fields.put("margin_top", top);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_margin_right">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_margin_right</a>
         */
        public ImageToPdfClient setMarginRight(String right) {
            if (!right.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(right, "setMarginRight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            
            fields.put("margin_right", right);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_margin_bottom">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_margin_bottom</a>
         */
        public ImageToPdfClient setMarginBottom(String bottom) {
            if (!bottom.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(bottom, "setMarginBottom", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            
            fields.put("margin_bottom", bottom);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_margin_left">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_margin_left</a>
         */
        public ImageToPdfClient setMarginLeft(String left) {
            if (!left.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(left, "setMarginLeft", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            
            fields.put("margin_left", left);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_margins">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_margins</a>
         */
        public ImageToPdfClient setPageMargins(String top, String right, String bottom, String left) {
            this.setMarginTop(top);
            this.setMarginRight(right);
            this.setMarginBottom(bottom);
            this.setMarginLeft(left);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_background_color">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_background_color</a>
         */
        public ImageToPdfClient setPageBackgroundColor(String color) {
            if (!color.matches("^[0-9a-fA-F]{6,8}$"))
                throw new Error(createInvalidValueMessage(color, "setPageBackgroundColor", "image-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            
            fields.put("page_background_color", color);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_dpi">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_dpi</a>
         */
        public ImageToPdfClient setDpi(int dpi) {
            fields.put("dpi", Integer.toString(dpi));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_watermark">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_watermark</a>
         */
        public ImageToPdfClient setPageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setPageWatermark", "image-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            
            files.put("page_watermark", watermark);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_watermark_url">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_watermark_url</a>
         */
        public ImageToPdfClient setPageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageWatermarkUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            
            fields.put("page_watermark_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_multipage_watermark">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_multipage_watermark</a>
         */
        public ImageToPdfClient setMultipageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setMultipageWatermark", "image-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            
            files.put("multipage_watermark", watermark);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_multipage_watermark_url">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_multipage_watermark_url</a>
         */
        public ImageToPdfClient setMultipageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageWatermarkUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            
            fields.put("multipage_watermark_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_background">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_background</a>
         */
        public ImageToPdfClient setPageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setPageBackground", "image-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            
            files.put("page_background", background);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_background_url">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_background_url</a>
         */
        public ImageToPdfClient setPageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageBackgroundUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            
            fields.put("page_background_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_multipage_background">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_multipage_background</a>
         */
        public ImageToPdfClient setMultipageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setMultipageBackground", "image-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            
            files.put("multipage_background", background);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_multipage_background_url">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_multipage_background_url</a>
         */
        public ImageToPdfClient setMultipageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageBackgroundUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            
            fields.put("multipage_background_url", url);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_linearize">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_linearize</a>
         */
        public ImageToPdfClient setLinearize(boolean value) {
            fields.put("linearize", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_encrypt">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_encrypt</a>
         */
        public ImageToPdfClient setEncrypt(boolean value) {
            fields.put("encrypt", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_user_password">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_user_password</a>
         */
        public ImageToPdfClient setUserPassword(String password) {
            fields.put("user_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_owner_password">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_owner_password</a>
         */
        public ImageToPdfClient setOwnerPassword(String password) {
            fields.put("owner_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_no_print">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_no_print</a>
         */
        public ImageToPdfClient setNoPrint(boolean value) {
            fields.put("no_print", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_no_modify">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_no_modify</a>
         */
        public ImageToPdfClient setNoModify(boolean value) {
            fields.put("no_modify", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_no_copy">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_no_copy</a>
         */
        public ImageToPdfClient setNoCopy(boolean value) {
            fields.put("no_copy", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_title">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_title</a>
         */
        public ImageToPdfClient setTitle(String title) {
            fields.put("title", title);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_subject">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_subject</a>
         */
        public ImageToPdfClient setSubject(String subject) {
            fields.put("subject", subject);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_author">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_author</a>
         */
        public ImageToPdfClient setAuthor(String author) {
            fields.put("author", author);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_keywords">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_keywords</a>
         */
        public ImageToPdfClient setKeywords(String keywords) {
            fields.put("keywords", keywords);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_layout">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_layout</a>
         */
        public ImageToPdfClient setPageLayout(String layout) {
            if (!layout.matches("(?i)^(single-page|one-column|two-column-left|two-column-right)$"))
                throw new Error(createInvalidValueMessage(layout, "setPageLayout", "image-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            
            fields.put("page_layout", layout);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_mode">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_page_mode</a>
         */
        public ImageToPdfClient setPageMode(String mode) {
            if (!mode.matches("(?i)^(full-screen|thumbnails|outlines)$"))
                throw new Error(createInvalidValueMessage(mode, "setPageMode", "image-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            
            fields.put("page_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_initial_zoom_type">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_initial_zoom_type</a>
         */
        public ImageToPdfClient setInitialZoomType(String zoomType) {
            if (!zoomType.matches("(?i)^(fit-width|fit-height|fit-page)$"))
                throw new Error(createInvalidValueMessage(zoomType, "setInitialZoomType", "image-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            
            fields.put("initial_zoom_type", zoomType);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_initial_page">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_initial_page</a>
         */
        public ImageToPdfClient setInitialPage(int page) {
            if (!(page > 0))
                throw new Error(createInvalidValueMessage(page, "setInitialPage", "image-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            
            fields.put("initial_page", Integer.toString(page));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_initial_zoom">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_initial_zoom</a>
         */
        public ImageToPdfClient setInitialZoom(int zoom) {
            if (!(zoom > 0))
                throw new Error(createInvalidValueMessage(zoom, "setInitialZoom", "image-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            
            fields.put("initial_zoom", Integer.toString(zoom));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_hide_toolbar">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_hide_toolbar</a>
         */
        public ImageToPdfClient setHideToolbar(boolean value) {
            fields.put("hide_toolbar", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_hide_menubar">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_hide_menubar</a>
         */
        public ImageToPdfClient setHideMenubar(boolean value) {
            fields.put("hide_menubar", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_hide_window_ui">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_hide_window_ui</a>
         */
        public ImageToPdfClient setHideWindowUi(boolean value) {
            fields.put("hide_window_ui", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_fit_window">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_fit_window</a>
         */
        public ImageToPdfClient setFitWindow(boolean value) {
            fields.put("fit_window", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_center_window">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_center_window</a>
         */
        public ImageToPdfClient setCenterWindow(boolean value) {
            fields.put("center_window", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_display_title">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_display_title</a>
         */
        public ImageToPdfClient setDisplayTitle(boolean value) {
            fields.put("display_title", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_debug_log">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_debug_log</a>
         */
        public ImageToPdfClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_debug_log_url">https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_debug_log_url</a>
         */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_remaining_credit_count">https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_remaining_credit_count</a>
         */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_consumed_credit_count">https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_consumed_credit_count</a>
         */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_job_id">https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_job_id</a>
         */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_output_size">https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_output_size</a>
         */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_version">https://pdfcrowd.com/api/image-to-pdf-java/ref/#get_version</a>
         */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_tag">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_tag</a>
         */
        public ImageToPdfClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_http_proxy">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_http_proxy</a>
         */
        public ImageToPdfClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_https_proxy">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_https_proxy</a>
         */
        public ImageToPdfClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_converter_version">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_converter_version</a>
         */
        public ImageToPdfClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(24.04|20.10|18.10|latest)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "image-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_use_http">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_use_http</a>
         */
        public ImageToPdfClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_client_user_agent">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_client_user_agent</a>
         */
        public ImageToPdfClient setClientUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_user_agent">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_user_agent</a>
         */
        public ImageToPdfClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_proxy">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_proxy</a>
         */
        public ImageToPdfClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_retry_count">https://pdfcrowd.com/api/image-to-pdf-java/ref/#set_retry_count</a>
         */
        public ImageToPdfClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

    /**
     * Conversion from PDF to HTML.
     *
     * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/">https://pdfcrowd.com/api/pdf-to-html-java/</a>
     */
    public static final class PdfToHtmlClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#PdfToHtmlClient">https://pdfcrowd.com/api/pdf-to-html-java/ref/#PdfToHtmlClient</a>
         */
        public PdfToHtmlClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "pdf");
            fields.put("output_format", "html");
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_url">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_url</a>
         */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_url_to_stream">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_url_to_stream</a>
         */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_url_to_file">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_url_to_file</a>
         */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertUrlToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_url_to_file"), 470);
            
            if (!(isOutputTypeValid(filePath)))
                throw new Error(createInvalidValueMessage(filePath, "convertUrlToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertUrlToStream(url, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_file">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_file</a>
         */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "pdf-to-html", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_file_to_stream">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_file_to_stream</a>
         */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "pdf-to-html", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_file_to_file">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_file_to_file</a>
         */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertFileToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_file_to_file"), 470);
            
            if (!(isOutputTypeValid(filePath)))
                throw new Error(createInvalidValueMessage(filePath, "convertFileToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertFileToStream(file, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_raw_data">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_raw_data</a>
         */
        public byte[] convertRawData(byte[] data) {
            rawData.put("file", data);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_raw_data_to_stream">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_raw_data_to_stream</a>
         */
        public void convertRawDataToStream(byte[] data, OutputStream outStream) {
            rawData.put("file", data);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_raw_data_to_file">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_raw_data_to_file</a>
         */
        public void convertRawDataToFile(byte[] data, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertRawDataToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            
            if (!(isOutputTypeValid(filePath)))
                throw new Error(createInvalidValueMessage(filePath, "convertRawDataToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_raw_data_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertRawDataToStream(data, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_stream">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_stream</a>
         */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_stream_to_stream">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_stream_to_stream</a>
         */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_stream_to_file">https://pdfcrowd.com/api/pdf-to-html-java/ref/#convert_stream_to_file</a>
         */
        public void convertStreamToFile(InputStream inStream, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStreamToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_stream_to_file"), 470);
            
            if (!(isOutputTypeValid(filePath)))
                throw new Error(createInvalidValueMessage(filePath, "convertStreamToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_stream_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStreamToStream(inStream, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_pdf_password">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_pdf_password</a>
         */
        public PdfToHtmlClient setPdfPassword(String password) {
            fields.put("pdf_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_scale_factor">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_scale_factor</a>
         */
        public PdfToHtmlClient setScaleFactor(int factor) {
            if (!(factor > 0))
                throw new Error(createInvalidValueMessage(factor, "setScaleFactor", "pdf-to-html", "Must be a positive integer.", "set_scale_factor"), 470);
            
            fields.put("scale_factor", Integer.toString(factor));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_print_page_range">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_print_page_range</a>
         */
        public PdfToHtmlClient setPrintPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPrintPageRange", "pdf-to-html", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            
            fields.put("print_page_range", pages);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_dpi">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_dpi</a>
         */
        public PdfToHtmlClient setDpi(int dpi) {
            fields.put("dpi", Integer.toString(dpi));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_image_mode">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_image_mode</a>
         */
        public PdfToHtmlClient setImageMode(String mode) {
            if (!mode.matches("(?i)^(embed|separate|none)$"))
                throw new Error(createInvalidValueMessage(mode, "setImageMode", "pdf-to-html", "Allowed values are embed, separate, none.", "set_image_mode"), 470);
            
            fields.put("image_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_image_format">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_image_format</a>
         */
        public PdfToHtmlClient setImageFormat(String imageFormat) {
            if (!imageFormat.matches("(?i)^(png|jpg|svg)$"))
                throw new Error(createInvalidValueMessage(imageFormat, "setImageFormat", "pdf-to-html", "Allowed values are png, jpg, svg.", "set_image_format"), 470);
            
            fields.put("image_format", imageFormat);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_css_mode">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_css_mode</a>
         */
        public PdfToHtmlClient setCssMode(String mode) {
            if (!mode.matches("(?i)^(embed|separate)$"))
                throw new Error(createInvalidValueMessage(mode, "setCssMode", "pdf-to-html", "Allowed values are embed, separate.", "set_css_mode"), 470);
            
            fields.put("css_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_font_mode">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_font_mode</a>
         */
        public PdfToHtmlClient setFontMode(String mode) {
            if (!mode.matches("(?i)^(embed|separate)$"))
                throw new Error(createInvalidValueMessage(mode, "setFontMode", "pdf-to-html", "Allowed values are embed, separate.", "set_font_mode"), 470);
            
            fields.put("font_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_type3_mode">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_type3_mode</a>
         */
        public PdfToHtmlClient setType3Mode(String mode) {
            if (!mode.matches("(?i)^(raster|convert)$"))
                throw new Error(createInvalidValueMessage(mode, "setType3Mode", "pdf-to-html", "Allowed values are raster, convert.", "set_type3_mode"), 470);
            
            fields.put("type3_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_split_ligatures">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_split_ligatures</a>
         */
        public PdfToHtmlClient setSplitLigatures(boolean value) {
            fields.put("split_ligatures", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_custom_css">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_custom_css</a>
         */
        public PdfToHtmlClient setCustomCss(String css) {
            if (!(css != null && !css.isEmpty()))
                throw new Error(createInvalidValueMessage(css, "setCustomCss", "pdf-to-html", "The string must not be empty.", "set_custom_css"), 470);
            
            fields.put("custom_css", css);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_html_namespace">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_html_namespace</a>
         */
        public PdfToHtmlClient setHtmlNamespace(String prefix) {
            if (!prefix.matches("(?i)^[a-z_][a-z0-9_:-]*$"))
                throw new Error(createInvalidValueMessage(prefix, "setHtmlNamespace", "pdf-to-html", "Start with a letter or underscore, and use only letters, numbers, hyphens, underscores, or colons.", "set_html_namespace"), 470);
            
            fields.put("html_namespace", prefix);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#is_zipped_output">https://pdfcrowd.com/api/pdf-to-html-java/ref/#is_zipped_output</a>
         */
        public boolean isZippedOutput() {
            return "separate".equals(fields.get("image_mode")) || "separate".equals(fields.get("css_mode")) || "separate".equals(fields.get("font_mode")) || "true".equals(fields.get("force_zip"));
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_force_zip">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_force_zip</a>
         */
        public PdfToHtmlClient setForceZip(boolean value) {
            fields.put("force_zip", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_title">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_title</a>
         */
        public PdfToHtmlClient setTitle(String title) {
            fields.put("title", title);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_subject">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_subject</a>
         */
        public PdfToHtmlClient setSubject(String subject) {
            fields.put("subject", subject);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_author">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_author</a>
         */
        public PdfToHtmlClient setAuthor(String author) {
            fields.put("author", author);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_keywords">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_keywords</a>
         */
        public PdfToHtmlClient setKeywords(String keywords) {
            fields.put("keywords", keywords);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_debug_log">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_debug_log</a>
         */
        public PdfToHtmlClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_debug_log_url">https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_debug_log_url</a>
         */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_remaining_credit_count">https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_remaining_credit_count</a>
         */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_consumed_credit_count">https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_consumed_credit_count</a>
         */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_job_id">https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_job_id</a>
         */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_page_count">https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_page_count</a>
         */
        public int getPageCount() {
            return helper.getPageCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_output_size">https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_output_size</a>
         */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_version">https://pdfcrowd.com/api/pdf-to-html-java/ref/#get_version</a>
         */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_tag">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_tag</a>
         */
        public PdfToHtmlClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_http_proxy">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_http_proxy</a>
         */
        public PdfToHtmlClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "pdf-to-html", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_https_proxy">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_https_proxy</a>
         */
        public PdfToHtmlClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "pdf-to-html", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_converter_version">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_converter_version</a>
         */
        public PdfToHtmlClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(24.04|20.10|18.10|latest)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "pdf-to-html", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_use_http">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_use_http</a>
         */
        public PdfToHtmlClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_client_user_agent">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_client_user_agent</a>
         */
        public PdfToHtmlClient setClientUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_user_agent">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_user_agent</a>
         */
        public PdfToHtmlClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_proxy">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_proxy</a>
         */
        public PdfToHtmlClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_retry_count">https://pdfcrowd.com/api/pdf-to-html-java/ref/#set_retry_count</a>
         */
        public PdfToHtmlClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

        private boolean isOutputTypeValid(String file_path) {
            String extension = "";
            int i = file_path.lastIndexOf('.');
            if(i > 0) {
                extension = file_path.substring(i);
            }
            return extension.equals(".zip") == isZippedOutput();
        }
    }

    /**
     * Conversion from PDF to text.
     *
     * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/">https://pdfcrowd.com/api/pdf-to-text-java/</a>
     */
    public static final class PdfToTextClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#PdfToTextClient">https://pdfcrowd.com/api/pdf-to-text-java/ref/#PdfToTextClient</a>
         */
        public PdfToTextClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "pdf");
            fields.put("output_format", "txt");
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_url">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_url</a>
         */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_url_to_stream">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_url_to_stream</a>
         */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_url_to_file">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_url_to_file</a>
         */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertUrlToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertUrlToStream(url, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_file">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_file</a>
         */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "pdf-to-text", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_file_to_stream">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_file_to_stream</a>
         */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "pdf-to-text", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_file_to_file">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_file_to_file</a>
         */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertFileToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertFileToStream(file, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_raw_data">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_raw_data</a>
         */
        public byte[] convertRawData(byte[] data) {
            rawData.put("file", data);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_raw_data_to_stream">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_raw_data_to_stream</a>
         */
        public void convertRawDataToStream(byte[] data, OutputStream outStream) {
            rawData.put("file", data);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_raw_data_to_file">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_raw_data_to_file</a>
         */
        public void convertRawDataToFile(byte[] data, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertRawDataToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertRawDataToStream(data, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_stream">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_stream</a>
         */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_stream_to_stream">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_stream_to_stream</a>
         */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_stream_to_file">https://pdfcrowd.com/api/pdf-to-text-java/ref/#convert_stream_to_file</a>
         */
        public void convertStreamToFile(InputStream inStream, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStreamToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_stream_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStreamToStream(inStream, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_pdf_password">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_pdf_password</a>
         */
        public PdfToTextClient setPdfPassword(String password) {
            fields.put("pdf_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_print_page_range">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_print_page_range</a>
         */
        public PdfToTextClient setPrintPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPrintPageRange", "pdf-to-text", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            
            fields.put("print_page_range", pages);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_no_layout">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_no_layout</a>
         */
        public PdfToTextClient setNoLayout(boolean value) {
            fields.put("no_layout", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_eol">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_eol</a>
         */
        public PdfToTextClient setEol(String eol) {
            if (!eol.matches("(?i)^(unix|dos|mac)$"))
                throw new Error(createInvalidValueMessage(eol, "setEol", "pdf-to-text", "Allowed values are unix, dos, mac.", "set_eol"), 470);
            
            fields.put("eol", eol);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_page_break_mode">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_page_break_mode</a>
         */
        public PdfToTextClient setPageBreakMode(String mode) {
            if (!mode.matches("(?i)^(none|default|custom)$"))
                throw new Error(createInvalidValueMessage(mode, "setPageBreakMode", "pdf-to-text", "Allowed values are none, default, custom.", "set_page_break_mode"), 470);
            
            fields.put("page_break_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_custom_page_break">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_custom_page_break</a>
         */
        public PdfToTextClient setCustomPageBreak(String pageBreak) {
            fields.put("custom_page_break", pageBreak);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_paragraph_mode">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_paragraph_mode</a>
         */
        public PdfToTextClient setParagraphMode(String mode) {
            if (!mode.matches("(?i)^(none|bounding-box|characters)$"))
                throw new Error(createInvalidValueMessage(mode, "setParagraphMode", "pdf-to-text", "Allowed values are none, bounding-box, characters.", "set_paragraph_mode"), 470);
            
            fields.put("paragraph_mode", mode);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_line_spacing_threshold">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_line_spacing_threshold</a>
         */
        public PdfToTextClient setLineSpacingThreshold(String threshold) {
            if (!threshold.matches("(?i)^0$|^[0-9]+%$"))
                throw new Error(createInvalidValueMessage(threshold, "setLineSpacingThreshold", "pdf-to-text", "The value must be a positive integer percentage.", "set_line_spacing_threshold"), 470);
            
            fields.put("line_spacing_threshold", threshold);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_remove_hyphenation">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_remove_hyphenation</a>
         */
        public PdfToTextClient setRemoveHyphenation(boolean value) {
            fields.put("remove_hyphenation", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_remove_empty_lines">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_remove_empty_lines</a>
         */
        public PdfToTextClient setRemoveEmptyLines(boolean value) {
            fields.put("remove_empty_lines", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area_x">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area_x</a>
         */
        public PdfToTextClient setCropAreaX(int x) {
            if (!(x >= 0))
                throw new Error(createInvalidValueMessage(x, "setCropAreaX", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_x"), 470);
            
            fields.put("crop_area_x", Integer.toString(x));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area_y">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area_y</a>
         */
        public PdfToTextClient setCropAreaY(int y) {
            if (!(y >= 0))
                throw new Error(createInvalidValueMessage(y, "setCropAreaY", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_y"), 470);
            
            fields.put("crop_area_y", Integer.toString(y));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area_width">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area_width</a>
         */
        public PdfToTextClient setCropAreaWidth(int width) {
            if (!(width >= 0))
                throw new Error(createInvalidValueMessage(width, "setCropAreaWidth", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_width"), 470);
            
            fields.put("crop_area_width", Integer.toString(width));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area_height">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area_height</a>
         */
        public PdfToTextClient setCropAreaHeight(int height) {
            if (!(height >= 0))
                throw new Error(createInvalidValueMessage(height, "setCropAreaHeight", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_height"), 470);
            
            fields.put("crop_area_height", Integer.toString(height));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_crop_area</a>
         */
        public PdfToTextClient setCropArea(int x, int y, int width, int height) {
            this.setCropAreaX(x);
            this.setCropAreaY(y);
            this.setCropAreaWidth(width);
            this.setCropAreaHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_debug_log">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_debug_log</a>
         */
        public PdfToTextClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_debug_log_url">https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_debug_log_url</a>
         */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_remaining_credit_count">https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_remaining_credit_count</a>
         */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_consumed_credit_count">https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_consumed_credit_count</a>
         */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_job_id">https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_job_id</a>
         */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_page_count">https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_page_count</a>
         */
        public int getPageCount() {
            return helper.getPageCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_output_size">https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_output_size</a>
         */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_version">https://pdfcrowd.com/api/pdf-to-text-java/ref/#get_version</a>
         */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_tag">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_tag</a>
         */
        public PdfToTextClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_http_proxy">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_http_proxy</a>
         */
        public PdfToTextClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "pdf-to-text", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_https_proxy">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_https_proxy</a>
         */
        public PdfToTextClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "pdf-to-text", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_use_http">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_use_http</a>
         */
        public PdfToTextClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_client_user_agent">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_client_user_agent</a>
         */
        public PdfToTextClient setClientUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_user_agent">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_user_agent</a>
         */
        public PdfToTextClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_proxy">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_proxy</a>
         */
        public PdfToTextClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_retry_count">https://pdfcrowd.com/api/pdf-to-text-java/ref/#set_retry_count</a>
         */
        public PdfToTextClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

    /**
     * Conversion from PDF to image.
     *
     * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/">https://pdfcrowd.com/api/pdf-to-image-java/</a>
     */
    public static final class PdfToImageClient {
        private ConnectionHelper helper;
        private HashMap<String,String> fields = new HashMap<String,String>();
        private HashMap<String,String> files = new HashMap<String,String>();
        private HashMap<String,byte[]> rawData = new HashMap<String,byte[]>();
        private int fileId = 1;

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#PdfToImageClient">https://pdfcrowd.com/api/pdf-to-image-java/ref/#PdfToImageClient</a>
         */
        public PdfToImageClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "pdf");
            fields.put("output_format", "png");
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_url">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_url</a>
         */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_url_to_stream">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_url_to_stream</a>
         */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_url_to_file">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_url_to_file</a>
         */
        public void convertUrlToFile(String url, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertUrlToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertUrlToStream(url, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_file">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_file</a>
         */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "pdf-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_file_to_stream">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_file_to_stream</a>
         */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "pdf-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_file_to_file">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_file_to_file</a>
         */
        public void convertFileToFile(String file, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertFileToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertFileToStream(file, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_raw_data">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_raw_data</a>
         */
        public byte[] convertRawData(byte[] data) {
            rawData.put("file", data);
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_raw_data_to_stream">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_raw_data_to_stream</a>
         */
        public void convertRawDataToStream(byte[] data, OutputStream outStream) {
            rawData.put("file", data);
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_raw_data_to_file">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_raw_data_to_file</a>
         */
        public void convertRawDataToFile(byte[] data, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertRawDataToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertRawDataToStream(data, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_stream">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_stream</a>
         */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_stream_to_stream">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_stream_to_stream</a>
         */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_stream_to_file">https://pdfcrowd.com/api/pdf-to-image-java/ref/#convert_stream_to_file</a>
         */
        public void convertStreamToFile(InputStream inStream, String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertStreamToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_stream_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            try {
                convertStreamToStream(inStream, outputFile);
                outputFile.close();
            }
            catch(Error why) {
                outputFile.close();
                new File(filePath).delete();
                throw why;
            }
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_output_format">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_output_format</a>
         */
        public PdfToImageClient setOutputFormat(String outputFormat) {
            if (!outputFormat.matches("(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$"))
                throw new Error(createInvalidValueMessage(outputFormat, "setOutputFormat", "pdf-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            
            fields.put("output_format", outputFormat);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_pdf_password">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_pdf_password</a>
         */
        public PdfToImageClient setPdfPassword(String password) {
            fields.put("pdf_password", password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_print_page_range">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_print_page_range</a>
         */
        public PdfToImageClient setPrintPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPrintPageRange", "pdf-to-image", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            
            fields.put("print_page_range", pages);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_dpi">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_dpi</a>
         */
        public PdfToImageClient setDpi(int dpi) {
            fields.put("dpi", Integer.toString(dpi));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#is_zipped_output">https://pdfcrowd.com/api/pdf-to-image-java/ref/#is_zipped_output</a>
         */
        public boolean isZippedOutput() {
            return "true".equals(fields.get("force_zip")) || this.getPageCount() > 1;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_force_zip">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_force_zip</a>
         */
        public PdfToImageClient setForceZip(boolean value) {
            fields.put("force_zip", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_use_cropbox">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_use_cropbox</a>
         */
        public PdfToImageClient setUseCropbox(boolean value) {
            fields.put("use_cropbox", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area_x">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area_x</a>
         */
        public PdfToImageClient setCropAreaX(int x) {
            if (!(x >= 0))
                throw new Error(createInvalidValueMessage(x, "setCropAreaX", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_x"), 470);
            
            fields.put("crop_area_x", Integer.toString(x));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area_y">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area_y</a>
         */
        public PdfToImageClient setCropAreaY(int y) {
            if (!(y >= 0))
                throw new Error(createInvalidValueMessage(y, "setCropAreaY", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_y"), 470);
            
            fields.put("crop_area_y", Integer.toString(y));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area_width">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area_width</a>
         */
        public PdfToImageClient setCropAreaWidth(int width) {
            if (!(width >= 0))
                throw new Error(createInvalidValueMessage(width, "setCropAreaWidth", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_width"), 470);
            
            fields.put("crop_area_width", Integer.toString(width));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area_height">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area_height</a>
         */
        public PdfToImageClient setCropAreaHeight(int height) {
            if (!(height >= 0))
                throw new Error(createInvalidValueMessage(height, "setCropAreaHeight", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_height"), 470);
            
            fields.put("crop_area_height", Integer.toString(height));
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_crop_area</a>
         */
        public PdfToImageClient setCropArea(int x, int y, int width, int height) {
            this.setCropAreaX(x);
            this.setCropAreaY(y);
            this.setCropAreaWidth(width);
            this.setCropAreaHeight(height);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_use_grayscale">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_use_grayscale</a>
         */
        public PdfToImageClient setUseGrayscale(boolean value) {
            fields.put("use_grayscale", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_debug_log">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_debug_log</a>
         */
        public PdfToImageClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_debug_log_url">https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_debug_log_url</a>
         */
        public String getDebugLogUrl() {
            return helper.getDebugLogUrl();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_remaining_credit_count">https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_remaining_credit_count</a>
         */
        public int getRemainingCreditCount() {
            return helper.getRemainingCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_consumed_credit_count">https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_consumed_credit_count</a>
         */
        public int getConsumedCreditCount() {
            return helper.getConsumedCreditCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_job_id">https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_job_id</a>
         */
        public String getJobId() {
            return helper.getJobId();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_page_count">https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_page_count</a>
         */
        public int getPageCount() {
            return helper.getPageCount();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_output_size">https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_output_size</a>
         */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_version">https://pdfcrowd.com/api/pdf-to-image-java/ref/#get_version</a>
         */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_tag">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_tag</a>
         */
        public PdfToImageClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_http_proxy">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_http_proxy</a>
         */
        public PdfToImageClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "pdf-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_https_proxy">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_https_proxy</a>
         */
        public PdfToImageClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "pdf-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_use_http">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_use_http</a>
         */
        public PdfToImageClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_client_user_agent">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_client_user_agent</a>
         */
        public PdfToImageClient setClientUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_user_agent">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_user_agent</a>
         */
        public PdfToImageClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_proxy">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_proxy</a>
         */
        public PdfToImageClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
         * @see <a href="https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_retry_count">https://pdfcrowd.com/api/pdf-to-image-java/ref/#set_retry_count</a>
         */
        public PdfToImageClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

}
