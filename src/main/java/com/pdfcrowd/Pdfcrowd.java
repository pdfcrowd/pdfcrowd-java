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
    public static final String CLIENT_VERSION = "5.18.0";

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
            setUserAgent("pdfcrowd_java_client/5.18.0 (https://pdfcrowd.com)");

            retryCount = 1;
            converterVersion = "20.10";
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
                    if ((err.getCode() == 502 || err.getCode() == 503) &&
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
                throw new Error("There was a problem connecting to Pdfcrowd servers over HTTPS:\n" +
                                e.toString() +
                                "\nYou can still use the API over HTTP, you just need to add the following line right after Pdfcrowd client initialization:\nclient.setUseHttp(true);",
                                481);
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
        String message = String.format("Invalid value '%s' for %s.", value, field);
        if(hint != null)
            {
                message += " " + hint;
            }
        return message + " " + String.format("Details: https://www.pdfcrowd.com/api/%s-java/ref/#%s", converter, id);
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
                throw new Error(createInvalidValueMessage(url, "convertUrl", "html-to-pdf", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
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
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "html-to-pdf", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
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
        * Convert a local file.
        *
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip).<br> If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            
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
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
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
        * Convert a string.
        *
        * @param text The string content to convert. The string must not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertString(String text) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "convertString", "html-to-pdf", "The string must not be empty.", "convert_string"), 470);
            
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
                throw new Error(createInvalidValueMessage(text, "convertStringToStream::text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470);
            
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
        * Convert the contents of an input stream.
        *
        * @param inStream The input stream with source data.<br> The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).<br>The archive can contain HTML code and its external assets (images, style sheets, javascript).
        * @return Byte array containing the conversion output.
        */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert the contents of an input stream and write the result to an output stream.
        *
        * @param inStream The input stream with source data.<br> The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).<br>The archive can contain HTML code and its external assets (images, style sheets, javascript).
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert the contents of an input stream and write the result to a local file.
        *
        * @param inStream The input stream with source data.<br> The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).<br>The archive can contain HTML code and its external assets (images, style sheets, javascript).
        * @param filePath The output file path. The string must not be empty.
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
        * Set the file name of the main HTML document stored in the input archive. If not specified, the first HTML file in the archive is used for conversion. Use this method if the input archive contains multiple HTML documents.
        *
        * @param filename The file name.
        * @return The converter object.
        */
        public HtmlToPdfClient setZipMainFilename(String filename) {
            fields.put("zip_main_filename", filename);
            return this;
        }

        /**
        * Set the output page size.
        *
        * @param size Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageSize(String size) {
            if (!size.matches("(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$"))
                throw new Error(createInvalidValueMessage(size, "setPageSize", "html-to-pdf", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            
            fields.put("page_size", size);
            return this;
        }

        /**
        * Set the output page width. The safe maximum is <span class='field-value'>200in</span> otherwise some PDF viewers may be unable to open the PDF.
        *
        * @param width The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setPageWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setPageWidth", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_page_width"), 470);
            
            fields.put("page_width", width);
            return this;
        }

        /**
        * Set the output page height. Use <span class='field-value'>-1</span> for a single page PDF. The safe maximum is <span class='field-value'>200in</span> otherwise some PDF viewers may be unable to open the PDF.
        *
        * @param height The value must be -1 or specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setPageHeight(String height) {
            if (!height.matches("(?i)^0$|^\\-1$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setPageHeight", "html-to-pdf", "The value must be -1 or specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_page_height"), 470);
            
            fields.put("page_height", height);
            return this;
        }

        /**
        * Set the output page dimensions.
        *
        * @param width Set the output page width. The safe maximum is <span class='field-value'>200in</span> otherwise some PDF viewers may be unable to open the PDF. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param height Set the output page height. Use <span class='field-value'>-1</span> for a single page PDF. The safe maximum is <span class='field-value'>200in</span> otherwise some PDF viewers may be unable to open the PDF. The value must be -1 or specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setPageDimensions(String width, String height) {
            this.setPageWidth(width);
            this.setPageHeight(height);
            return this;
        }

        /**
        * Set the output page orientation.
        *
        * @param orientation Allowed values are landscape, portrait.
        * @return The converter object.
        */
        public HtmlToPdfClient setOrientation(String orientation) {
            if (!orientation.matches("(?i)^(landscape|portrait)$"))
                throw new Error(createInvalidValueMessage(orientation, "setOrientation", "html-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            
            fields.put("orientation", orientation);
            return this;
        }

        /**
        * Set the output page top margin.
        *
        * @param top The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setMarginTop(String top) {
            if (!top.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(top, "setMarginTop", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_top"), 470);
            
            fields.put("margin_top", top);
            return this;
        }

        /**
        * Set the output page right margin.
        *
        * @param right The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setMarginRight(String right) {
            if (!right.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(right, "setMarginRight", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_right"), 470);
            
            fields.put("margin_right", right);
            return this;
        }

        /**
        * Set the output page bottom margin.
        *
        * @param bottom The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setMarginBottom(String bottom) {
            if (!bottom.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(bottom, "setMarginBottom", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_bottom"), 470);
            
            fields.put("margin_bottom", bottom);
            return this;
        }

        /**
        * Set the output page left margin.
        *
        * @param left The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setMarginLeft(String left) {
            if (!left.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(left, "setMarginLeft", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_left"), 470);
            
            fields.put("margin_left", left);
            return this;
        }

        /**
        * Disable page margins.
        *
        * @param value Set to <span class='field-value'>true</span> to disable margins.
        * @return The converter object.
        */
        public HtmlToPdfClient setNoMargins(boolean value) {
            fields.put("no_margins", value ? "true" : null);
            return this;
        }

        /**
        * Set the output page margins.
        *
        * @param top Set the output page top margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param right Set the output page right margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param bottom Set the output page bottom margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param left Set the output page left margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setPageMargins(String top, String right, String bottom, String left) {
            this.setMarginTop(top);
            this.setMarginRight(right);
            this.setMarginBottom(bottom);
            this.setMarginLeft(left);
            return this;
        }

        /**
        * Set the page range to print.
        *
        * @param pages A comma separated list of page numbers or ranges.
        * @return The converter object.
        */
        public HtmlToPdfClient setPrintPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPrintPageRange", "html-to-pdf", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            
            fields.put("print_page_range", pages);
            return this;
        }

        /**
        * Set an offset between physical and logical page numbers.
        *
        * @param offset Integer specifying page offset.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageNumberingOffset(int offset) {
            fields.put("page_numbering_offset", Integer.toString(offset));
            return this;
        }

        /**
        * Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
        *
        * @param x The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt". It may contain a negative value.
        * @return The converter object.
        */
        public HtmlToPdfClient setContentAreaX(String x) {
            if (!x.matches("(?i)^0$|^\\-?[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(x, "setContentAreaX", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\". It may contain a negative value.", "set_content_area_x"), 470);
            
            fields.put("content_area_x", x);
            return this;
        }

        /**
        * Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
        *
        * @param y The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt". It may contain a negative value.
        * @return The converter object.
        */
        public HtmlToPdfClient setContentAreaY(String y) {
            if (!y.matches("(?i)^0$|^\\-?[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(y, "setContentAreaY", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\". It may contain a negative value.", "set_content_area_y"), 470);
            
            fields.put("content_area_y", y);
            return this;
        }

        /**
        * Set the width of the content area. It should be at least 1 inch.
        *
        * @param width The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setContentAreaWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setContentAreaWidth", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_content_area_width"), 470);
            
            fields.put("content_area_width", width);
            return this;
        }

        /**
        * Set the height of the content area. It should be at least 1 inch.
        *
        * @param height The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setContentAreaHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setContentAreaHeight", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_content_area_height"), 470);
            
            fields.put("content_area_height", height);
            return this;
        }

        /**
        * Set the content area position and size. The content area enables to specify a web page area to be converted.
        *
        * @param x Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt". It may contain a negative value.
        * @param y Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt". It may contain a negative value.
        * @param width Set the width of the content area. It should be at least 1 inch. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param height Set the height of the content area. It should be at least 1 inch. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setContentArea(String x, String y, String width, String height) {
            this.setContentAreaX(x);
            this.setContentAreaY(y);
            this.setContentAreaWidth(width);
            this.setContentAreaHeight(height);
            return this;
        }

        /**
        * Specifies behavior in presence of CSS @page rules. It may affect the page size, margins and orientation.
        *
        * @param mode The page rule mode. Allowed values are default, mode1, mode2.
        * @return The converter object.
        */
        public HtmlToPdfClient setCssPageRuleMode(String mode) {
            if (!mode.matches("(?i)^(default|mode1|mode2)$"))
                throw new Error(createInvalidValueMessage(mode, "setCssPageRuleMode", "html-to-pdf", "Allowed values are default, mode1, mode2.", "set_css_page_rule_mode"), 470);
            
            fields.put("css_page_rule_mode", mode);
            return this;
        }

        /**
        * Specifies which blank pages to exclude from the output document.
        *
        * @param pages The empty page behavior. Allowed values are trailing, none.
        * @return The converter object.
        */
        public HtmlToPdfClient setRemoveBlankPages(String pages) {
            if (!pages.matches("(?i)^(trailing|none)$"))
                throw new Error(createInvalidValueMessage(pages, "setRemoveBlankPages", "html-to-pdf", "Allowed values are trailing, none.", "set_remove_blank_pages"), 470);
            
            fields.put("remove_blank_pages", pages);
            return this;
        }

        /**
        * Load an HTML code from the specified URL and use it as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: <ul> <li><span class='field-value'>pdfcrowd-page-count</span> - the total page count of printed pages</li> <li><span class='field-value'>pdfcrowd-page-number</span> - the current page number</li> <li><span class='field-value'>pdfcrowd-source-url</span> - the source URL of the converted document</li> <li><span class='field-value'>pdfcrowd-source-title</span> - the title of the converted document</li> </ul> The following attributes can be used: <ul> <li><span class='field-value'>data-pdfcrowd-number-format</span> - specifies the type of the used numerals. Allowed values: <ul> <li><span class='field-value'>arabic</span> - Arabic numerals, they are used by default</li> <li><span class='field-value'>roman</span> - Roman numerals</li> <li><span class='field-value'>eastern-arabic</span> - Eastern Arabic numerals</li> <li><span class='field-value'>bengali</span> - Bengali numerals</li> <li><span class='field-value'>devanagari</span> - Devanagari numerals</li> <li><span class='field-value'>thai</span> - Thai numerals</li> <li><span class='field-value'>east-asia</span> - Chinese, Vietnamese, Japanese and Korean numerals</li> <li><span class='field-value'>chinese-formal</span> - Chinese formal numerals</li> </ul> Please contact us if you need another type of numerals.<br> Example:<br> &lt;span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'&gt;&lt;/span&gt; </li> <li><span class='field-value'>data-pdfcrowd-placement</span> - specifies where to place the source URL. Allowed values: <ul> <li>The URL is inserted to the content <ul> <li> Example: &lt;span class='pdfcrowd-source-url'&gt;&lt;/span&gt;<br> will produce &lt;span&gt;http://example.com&lt;/span&gt; </li> </ul> </li> <li><span class='field-value'>href</span> - the URL is set to the href attribute <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'&gt;Link to source&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;Link to source&lt;/a&gt; </li> </ul> </li> <li><span class='field-value'>href-and-content</span> - the URL is set to the href attribute and to the content <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'&gt;&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;http://example.com&lt;/a&gt; </li> </ul> </li> </ul> </li> </ul>
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public HtmlToPdfClient setHeaderUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setHeaderUrl", "html-to-pdf", "The supported protocols are http:// and https://.", "set_header_url"), 470);
            
            fields.put("header_url", url);
            return this;
        }

        /**
        * Use the specified HTML code as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: <ul> <li><span class='field-value'>pdfcrowd-page-count</span> - the total page count of printed pages</li> <li><span class='field-value'>pdfcrowd-page-number</span> - the current page number</li> <li><span class='field-value'>pdfcrowd-source-url</span> - the source URL of the converted document</li> <li><span class='field-value'>pdfcrowd-source-title</span> - the title of the converted document</li> </ul> The following attributes can be used: <ul> <li><span class='field-value'>data-pdfcrowd-number-format</span> - specifies the type of the used numerals. Allowed values: <ul> <li><span class='field-value'>arabic</span> - Arabic numerals, they are used by default</li> <li><span class='field-value'>roman</span> - Roman numerals</li> <li><span class='field-value'>eastern-arabic</span> - Eastern Arabic numerals</li> <li><span class='field-value'>bengali</span> - Bengali numerals</li> <li><span class='field-value'>devanagari</span> - Devanagari numerals</li> <li><span class='field-value'>thai</span> - Thai numerals</li> <li><span class='field-value'>east-asia</span> - Chinese, Vietnamese, Japanese and Korean numerals</li> <li><span class='field-value'>chinese-formal</span> - Chinese formal numerals</li> </ul> Please contact us if you need another type of numerals.<br> Example:<br> &lt;span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'&gt;&lt;/span&gt; </li> <li><span class='field-value'>data-pdfcrowd-placement</span> - specifies where to place the source URL. Allowed values: <ul> <li>The URL is inserted to the content <ul> <li> Example: &lt;span class='pdfcrowd-source-url'&gt;&lt;/span&gt;<br> will produce &lt;span&gt;http://example.com&lt;/span&gt; </li> </ul> </li> <li><span class='field-value'>href</span> - the URL is set to the href attribute <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'&gt;Link to source&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;Link to source&lt;/a&gt; </li> </ul> </li> <li><span class='field-value'>href-and-content</span> - the URL is set to the href attribute and to the content <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'&gt;&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;http://example.com&lt;/a&gt; </li> </ul> </li> </ul> </li> </ul>
        *
        * @param html The string must not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setHeaderHtml(String html) {
            if (!(html != null && !html.isEmpty()))
                throw new Error(createInvalidValueMessage(html, "setHeaderHtml", "html-to-pdf", "The string must not be empty.", "set_header_html"), 470);
            
            fields.put("header_html", html);
            return this;
        }

        /**
        * Set the header height.
        *
        * @param height The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setHeaderHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setHeaderHeight", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_header_height"), 470);
            
            fields.put("header_height", height);
            return this;
        }

        /**
        * Set the file name of the header HTML document stored in the input archive. Use this method if the input archive contains multiple HTML documents.
        *
        * @param filename The file name.
        * @return The converter object.
        */
        public HtmlToPdfClient setZipHeaderFilename(String filename) {
            fields.put("zip_header_filename", filename);
            return this;
        }

        /**
        * Load an HTML code from the specified URL and use it as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: <ul> <li><span class='field-value'>pdfcrowd-page-count</span> - the total page count of printed pages</li> <li><span class='field-value'>pdfcrowd-page-number</span> - the current page number</li> <li><span class='field-value'>pdfcrowd-source-url</span> - the source URL of the converted document</li> <li><span class='field-value'>pdfcrowd-source-title</span> - the title of the converted document</li> </ul> The following attributes can be used: <ul> <li><span class='field-value'>data-pdfcrowd-number-format</span> - specifies the type of the used numerals. Allowed values: <ul> <li><span class='field-value'>arabic</span> - Arabic numerals, they are used by default</li> <li><span class='field-value'>roman</span> - Roman numerals</li> <li><span class='field-value'>eastern-arabic</span> - Eastern Arabic numerals</li> <li><span class='field-value'>bengali</span> - Bengali numerals</li> <li><span class='field-value'>devanagari</span> - Devanagari numerals</li> <li><span class='field-value'>thai</span> - Thai numerals</li> <li><span class='field-value'>east-asia</span> - Chinese, Vietnamese, Japanese and Korean numerals</li> <li><span class='field-value'>chinese-formal</span> - Chinese formal numerals</li> </ul> Please contact us if you need another type of numerals.<br> Example:<br> &lt;span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'&gt;&lt;/span&gt; </li> <li><span class='field-value'>data-pdfcrowd-placement</span> - specifies where to place the source URL. Allowed values: <ul> <li>The URL is inserted to the content <ul> <li> Example: &lt;span class='pdfcrowd-source-url'&gt;&lt;/span&gt;<br> will produce &lt;span&gt;http://example.com&lt;/span&gt; </li> </ul> </li> <li><span class='field-value'>href</span> - the URL is set to the href attribute <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'&gt;Link to source&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;Link to source&lt;/a&gt; </li> </ul> </li> <li><span class='field-value'>href-and-content</span> - the URL is set to the href attribute and to the content <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'&gt;&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;http://example.com&lt;/a&gt; </li> </ul> </li> </ul> </li> </ul>
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public HtmlToPdfClient setFooterUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setFooterUrl", "html-to-pdf", "The supported protocols are http:// and https://.", "set_footer_url"), 470);
            
            fields.put("footer_url", url);
            return this;
        }

        /**
        * Use the specified HTML as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: <ul> <li><span class='field-value'>pdfcrowd-page-count</span> - the total page count of printed pages</li> <li><span class='field-value'>pdfcrowd-page-number</span> - the current page number</li> <li><span class='field-value'>pdfcrowd-source-url</span> - the source URL of the converted document</li> <li><span class='field-value'>pdfcrowd-source-title</span> - the title of the converted document</li> </ul> The following attributes can be used: <ul> <li><span class='field-value'>data-pdfcrowd-number-format</span> - specifies the type of the used numerals. Allowed values: <ul> <li><span class='field-value'>arabic</span> - Arabic numerals, they are used by default</li> <li><span class='field-value'>roman</span> - Roman numerals</li> <li><span class='field-value'>eastern-arabic</span> - Eastern Arabic numerals</li> <li><span class='field-value'>bengali</span> - Bengali numerals</li> <li><span class='field-value'>devanagari</span> - Devanagari numerals</li> <li><span class='field-value'>thai</span> - Thai numerals</li> <li><span class='field-value'>east-asia</span> - Chinese, Vietnamese, Japanese and Korean numerals</li> <li><span class='field-value'>chinese-formal</span> - Chinese formal numerals</li> </ul> Please contact us if you need another type of numerals.<br> Example:<br> &lt;span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'&gt;&lt;/span&gt; </li> <li><span class='field-value'>data-pdfcrowd-placement</span> - specifies where to place the source URL. Allowed values: <ul> <li>The URL is inserted to the content <ul> <li> Example: &lt;span class='pdfcrowd-source-url'&gt;&lt;/span&gt;<br> will produce &lt;span&gt;http://example.com&lt;/span&gt; </li> </ul> </li> <li><span class='field-value'>href</span> - the URL is set to the href attribute <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'&gt;Link to source&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;Link to source&lt;/a&gt; </li> </ul> </li> <li><span class='field-value'>href-and-content</span> - the URL is set to the href attribute and to the content <ul> <li> Example: &lt;a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'&gt;&lt;/a&gt;<br> will produce &lt;a href='http://example.com'&gt;http://example.com&lt;/a&gt; </li> </ul> </li> </ul> </li> </ul>
        *
        * @param html The string must not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setFooterHtml(String html) {
            if (!(html != null && !html.isEmpty()))
                throw new Error(createInvalidValueMessage(html, "setFooterHtml", "html-to-pdf", "The string must not be empty.", "set_footer_html"), 470);
            
            fields.put("footer_html", html);
            return this;
        }

        /**
        * Set the footer height.
        *
        * @param height The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public HtmlToPdfClient setFooterHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setFooterHeight", "html-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_footer_height"), 470);
            
            fields.put("footer_height", height);
            return this;
        }

        /**
        * Set the file name of the footer HTML document stored in the input archive. Use this method if the input archive contains multiple HTML documents.
        *
        * @param filename The file name.
        * @return The converter object.
        */
        public HtmlToPdfClient setZipFooterFilename(String filename) {
            fields.put("zip_footer_filename", filename);
            return this;
        }

        /**
        * Disable horizontal page margins for header and footer. The header/footer contents width will be equal to the physical page width.
        *
        * @param value Set to <span class='field-value'>true</span> to disable horizontal margins for header and footer.
        * @return The converter object.
        */
        public HtmlToPdfClient setNoHeaderFooterHorizontalMargins(boolean value) {
            fields.put("no_header_footer_horizontal_margins", value ? "true" : null);
            return this;
        }

        /**
        * The page header is not printed on the specified pages.
        *
        * @param pages List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
        * @return The converter object.
        */
        public HtmlToPdfClient setExcludeHeaderOnPages(String pages) {
            if (!pages.matches("^(?:\\s*\\-?\\d+\\s*,)*\\s*\\-?\\d+\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setExcludeHeaderOnPages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_header_on_pages"), 470);
            
            fields.put("exclude_header_on_pages", pages);
            return this;
        }

        /**
        * The page footer is not printed on the specified pages.
        *
        * @param pages List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
        * @return The converter object.
        */
        public HtmlToPdfClient setExcludeFooterOnPages(String pages) {
            if (!pages.matches("^(?:\\s*\\-?\\d+\\s*,)*\\s*\\-?\\d+\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setExcludeFooterOnPages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_footer_on_pages"), 470);
            
            fields.put("exclude_footer_on_pages", pages);
            return this;
        }

        /**
        * Set the scaling factor (zoom) for the header and footer.
        *
        * @param factor The percentage value. The value must be in the range 10-500.
        * @return The converter object.
        */
        public HtmlToPdfClient setHeaderFooterScaleFactor(int factor) {
            if (!(factor >= 10 && factor <= 500))
                throw new Error(createInvalidValueMessage(factor, "setHeaderFooterScaleFactor", "html-to-pdf", "The value must be in the range 10-500.", "set_header_footer_scale_factor"), 470);
            
            fields.put("header_footer_scale_factor", Integer.toString(factor));
            return this;
        }

        /**
        * Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        *
        * @param watermark The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setPageWatermark", "html-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            
            files.put("page_watermark", watermark);
            return this;
        }

        /**
        * Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageWatermarkUrl", "html-to-pdf", "The supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            
            fields.put("page_watermark_url", url);
            return this;
        }

        /**
        * Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        *
        * @param watermark The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setMultipageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setMultipageWatermark", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            
            files.put("multipage_watermark", watermark);
            return this;
        }

        /**
        * Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public HtmlToPdfClient setMultipageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageWatermarkUrl", "html-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            
            fields.put("multipage_watermark_url", url);
            return this;
        }

        /**
        * Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        *
        * @param background The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setPageBackground", "html-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            
            files.put("page_background", background);
            return this;
        }

        /**
        * Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageBackgroundUrl", "html-to-pdf", "The supported protocols are http:// and https://.", "set_page_background_url"), 470);
            
            fields.put("page_background_url", url);
            return this;
        }

        /**
        * Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        *
        * @param background The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setMultipageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setMultipageBackground", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            
            files.put("multipage_background", background);
            return this;
        }

        /**
        * Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public HtmlToPdfClient setMultipageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageBackgroundUrl", "html-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            
            fields.put("multipage_background_url", url);
            return this;
        }

        /**
        * The page background color in RGB or RGBA hexadecimal format. The color fills the entire page regardless of the margins.
        *
        * @param color The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageBackgroundColor(String color) {
            if (!color.matches("^[0-9a-fA-F]{6,8}$"))
                throw new Error(createInvalidValueMessage(color, "setPageBackgroundColor", "html-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            
            fields.put("page_background_color", color);
            return this;
        }

        /**
        * Use the print version of the page if available (@media print).
        *
        * @param value Set to <span class='field-value'>true</span> to use the print version of the page.
        * @return The converter object.
        */
        public HtmlToPdfClient setUsePrintMedia(boolean value) {
            fields.put("use_print_media", value ? "true" : null);
            return this;
        }

        /**
        * Do not print the background graphics.
        *
        * @param value Set to <span class='field-value'>true</span> to disable the background graphics.
        * @return The converter object.
        */
        public HtmlToPdfClient setNoBackground(boolean value) {
            fields.put("no_background", value ? "true" : null);
            return this;
        }

        /**
        * Do not execute JavaScript.
        *
        * @param value Set to <span class='field-value'>true</span> to disable JavaScript in web pages.
        * @return The converter object.
        */
        public HtmlToPdfClient setDisableJavascript(boolean value) {
            fields.put("disable_javascript", value ? "true" : null);
            return this;
        }

        /**
        * Do not load images.
        *
        * @param value Set to <span class='field-value'>true</span> to disable loading of images.
        * @return The converter object.
        */
        public HtmlToPdfClient setDisableImageLoading(boolean value) {
            fields.put("disable_image_loading", value ? "true" : null);
            return this;
        }

        /**
        * Disable loading fonts from remote sources.
        *
        * @param value Set to <span class='field-value'>true</span> disable loading remote fonts.
        * @return The converter object.
        */
        public HtmlToPdfClient setDisableRemoteFonts(boolean value) {
            fields.put("disable_remote_fonts", value ? "true" : null);
            return this;
        }

        /**
        * Use a mobile user agent.
        *
        * @param value Set to <span class='field-value'>true</span> to use a mobile user agent.
        * @return The converter object.
        */
        public HtmlToPdfClient setUseMobileUserAgent(boolean value) {
            fields.put("use_mobile_user_agent", value ? "true" : null);
            return this;
        }

        /**
        * Specifies how iframes are handled.
        *
        * @param iframes Allowed values are all, same-origin, none.
        * @return The converter object.
        */
        public HtmlToPdfClient setLoadIframes(String iframes) {
            if (!iframes.matches("(?i)^(all|same-origin|none)$"))
                throw new Error(createInvalidValueMessage(iframes, "setLoadIframes", "html-to-pdf", "Allowed values are all, same-origin, none.", "set_load_iframes"), 470);
            
            fields.put("load_iframes", iframes);
            return this;
        }

        /**
        * Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
        *
        * @param value Set to <span class='field-value'>true</span> to block ads in web pages.
        * @return The converter object.
        */
        public HtmlToPdfClient setBlockAds(boolean value) {
            fields.put("block_ads", value ? "true" : null);
            return this;
        }

        /**
        * Set the default HTML content text encoding.
        *
        * @param encoding The text encoding of the HTML content.
        * @return The converter object.
        */
        public HtmlToPdfClient setDefaultEncoding(String encoding) {
            fields.put("default_encoding", encoding);
            return this;
        }

        /**
        * Set the locale for the conversion. This may affect the output format of dates, times and numbers.
        *
        * @param locale The locale code according to ISO 639.
        * @return The converter object.
        */
        public HtmlToPdfClient setLocale(String locale) {
            fields.put("locale", locale);
            return this;
        }

        /**
        * Set the HTTP authentication user name.
        *
        * @param userName The user name.
        * @return The converter object.
        */
        public HtmlToPdfClient setHttpAuthUserName(String userName) {
            fields.put("http_auth_user_name", userName);
            return this;
        }

        /**
        * Set the HTTP authentication password.
        *
        * @param password The password.
        * @return The converter object.
        */
        public HtmlToPdfClient setHttpAuthPassword(String password) {
            fields.put("http_auth_password", password);
            return this;
        }

        /**
        * Set credentials to access HTTP base authentication protected websites.
        *
        * @param userName Set the HTTP authentication user name.
        * @param password Set the HTTP authentication password.
        * @return The converter object.
        */
        public HtmlToPdfClient setHttpAuth(String userName, String password) {
            this.setHttpAuthUserName(userName);
            this.setHttpAuthPassword(password);
            return this;
        }

        /**
        * Set cookies that are sent in Pdfcrowd HTTP requests.
        *
        * @param cookies The cookie string.
        * @return The converter object.
        */
        public HtmlToPdfClient setCookies(String cookies) {
            fields.put("cookies", cookies);
            return this;
        }

        /**
        * Do not allow insecure HTTPS connections.
        *
        * @param value Set to <span class='field-value'>true</span> to enable SSL certificate verification.
        * @return The converter object.
        */
        public HtmlToPdfClient setVerifySslCertificates(boolean value) {
            fields.put("verify_ssl_certificates", value ? "true" : null);
            return this;
        }

        /**
        * Abort the conversion if the main URL HTTP status code is greater than or equal to 400.
        *
        * @param failOnError Set to <span class='field-value'>true</span> to abort the conversion.
        * @return The converter object.
        */
        public HtmlToPdfClient setFailOnMainUrlError(boolean failOnError) {
            fields.put("fail_on_main_url_error", failOnError ? "true" : null);
            return this;
        }

        /**
        * Abort the conversion if any of the sub-request HTTP status code is greater than or equal to 400 or if some sub-requests are still pending. See details in a debug log.
        *
        * @param failOnError Set to <span class='field-value'>true</span> to abort the conversion.
        * @return The converter object.
        */
        public HtmlToPdfClient setFailOnAnyUrlError(boolean failOnError) {
            fields.put("fail_on_any_url_error", failOnError ? "true" : null);
            return this;
        }

        /**
        * Do not send the X-Pdfcrowd HTTP header in Pdfcrowd HTTP requests.
        *
        * @param value Set to <span class='field-value'>true</span> to disable sending X-Pdfcrowd HTTP header.
        * @return The converter object.
        */
        public HtmlToPdfClient setNoXpdfcrowdHeader(boolean value) {
            fields.put("no_xpdfcrowd_header", value ? "true" : null);
            return this;
        }

        /**
        * Apply custom CSS to the input HTML document. It allows you to modify the visual appearance and layout of your HTML content dynamically. Tip: Using <span class='field-value'>!important</span> in custom CSS provides a way to prioritize and override conflicting styles.
        *
        * @param css A string containing valid CSS. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setCustomCss(String css) {
            if (!(css != null && !css.isEmpty()))
                throw new Error(createInvalidValueMessage(css, "setCustomCss", "html-to-pdf", "The string must not be empty.", "set_custom_css"), 470);
            
            fields.put("custom_css", css);
            return this;
        }

        /**
        * Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our <a href='/api/libpdfcrowd/'>JavaScript library</a>.
        *
        * @param javascript A string containing a JavaScript code. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setCustomJavascript(String javascript) {
            if (!(javascript != null && !javascript.isEmpty()))
                throw new Error(createInvalidValueMessage(javascript, "setCustomJavascript", "html-to-pdf", "The string must not be empty.", "set_custom_javascript"), 470);
            
            fields.put("custom_javascript", javascript);
            return this;
        }

        /**
        * Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our <a href='/api/libpdfcrowd/'>JavaScript library</a>.
        *
        * @param javascript A string containing a JavaScript code. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setOnLoadJavascript(String javascript) {
            if (!(javascript != null && !javascript.isEmpty()))
                throw new Error(createInvalidValueMessage(javascript, "setOnLoadJavascript", "html-to-pdf", "The string must not be empty.", "set_on_load_javascript"), 470);
            
            fields.put("on_load_javascript", javascript);
            return this;
        }

        /**
        * Set a custom HTTP header that is sent in Pdfcrowd HTTP requests.
        *
        * @param header A string containing the header name and value separated by a colon.
        * @return The converter object.
        */
        public HtmlToPdfClient setCustomHttpHeader(String header) {
            if (!header.matches("^.+:.+$"))
                throw new Error(createInvalidValueMessage(header, "setCustomHttpHeader", "html-to-pdf", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            
            fields.put("custom_http_header", header);
            return this;
        }

        /**
        * Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your API license defines the maximum wait time by "Max Delay" parameter.
        *
        * @param delay The number of milliseconds to wait. Must be a positive integer number or 0.
        * @return The converter object.
        */
        public HtmlToPdfClient setJavascriptDelay(int delay) {
            if (!(delay >= 0))
                throw new Error(createInvalidValueMessage(delay, "setJavascriptDelay", "html-to-pdf", "Must be a positive integer number or 0.", "set_javascript_delay"), 470);
            
            fields.put("javascript_delay", Integer.toString(delay));
            return this;
        }

        /**
        * Convert only the specified element from the main document and its children. The element is specified by one or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a>. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
        *
        * @param selectors One or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a> separated by commas. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setElementToConvert(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "setElementToConvert", "html-to-pdf", "The string must not be empty.", "set_element_to_convert"), 470);
            
            fields.put("element_to_convert", selectors);
            return this;
        }

        /**
        * Specify the DOM handling when only a part of the document is converted. This can affect the CSS rules used.
        *
        * @param mode Allowed values are cut-out, remove-siblings, hide-siblings.
        * @return The converter object.
        */
        public HtmlToPdfClient setElementToConvertMode(String mode) {
            if (!mode.matches("(?i)^(cut-out|remove-siblings|hide-siblings)$"))
                throw new Error(createInvalidValueMessage(mode, "setElementToConvertMode", "html-to-pdf", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            
            fields.put("element_to_convert_mode", mode);
            return this;
        }

        /**
        * Wait for the specified element in a source document. The element is specified by one or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a>. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your API license defines the maximum wait time by "Max Delay" parameter.
        *
        * @param selectors One or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a> separated by commas. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setWaitForElement(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "setWaitForElement", "html-to-pdf", "The string must not be empty.", "set_wait_for_element"), 470);
            
            fields.put("wait_for_element", selectors);
            return this;
        }

        /**
        * The main HTML element for conversion is detected automatically.
        *
        * @param value Set to <span class='field-value'>true</span> to detect the main element.
        * @return The converter object.
        */
        public HtmlToPdfClient setAutoDetectElementToConvert(boolean value) {
            fields.put("auto_detect_element_to_convert", value ? "true" : null);
            return this;
        }

        /**
        * The input HTML is automatically enhanced to improve the readability.
        *
        * @param enhancements Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.
        * @return The converter object.
        */
        public HtmlToPdfClient setReadabilityEnhancements(String enhancements) {
            if (!enhancements.matches("(?i)^(none|readability-v1|readability-v2|readability-v3|readability-v4)$"))
                throw new Error(createInvalidValueMessage(enhancements, "setReadabilityEnhancements", "html-to-pdf", "Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.", "set_readability_enhancements"), 470);
            
            fields.put("readability_enhancements", enhancements);
            return this;
        }

        /**
        * Set the viewport width in pixels. The viewport is the user's visible area of the page.
        *
        * @param width The value must be in the range 96-65000.
        * @return The converter object.
        */
        public HtmlToPdfClient setViewportWidth(int width) {
            if (!(width >= 96 && width <= 65000))
                throw new Error(createInvalidValueMessage(width, "setViewportWidth", "html-to-pdf", "The value must be in the range 96-65000.", "set_viewport_width"), 470);
            
            fields.put("viewport_width", Integer.toString(width));
            return this;
        }

        /**
        * Set the viewport height in pixels. The viewport is the user's visible area of the page. If the input HTML uses lazily loaded images, try using a large value that covers the entire height of the HTML, e.g. 100000.
        *
        * @param height Must be a positive integer number.
        * @return The converter object.
        */
        public HtmlToPdfClient setViewportHeight(int height) {
            if (!(height > 0))
                throw new Error(createInvalidValueMessage(height, "setViewportHeight", "html-to-pdf", "Must be a positive integer number.", "set_viewport_height"), 470);
            
            fields.put("viewport_height", Integer.toString(height));
            return this;
        }

        /**
        * Set the viewport size. The viewport is the user's visible area of the page.
        *
        * @param width Set the viewport width in pixels. The viewport is the user's visible area of the page. The value must be in the range 96-65000.
        * @param height Set the viewport height in pixels. The viewport is the user's visible area of the page. If the input HTML uses lazily loaded images, try using a large value that covers the entire height of the HTML, e.g. 100000. Must be a positive integer number.
        * @return The converter object.
        */
        public HtmlToPdfClient setViewport(int width, int height) {
            this.setViewportWidth(width);
            this.setViewportHeight(height);
            return this;
        }

        /**
        * Set the rendering mode.
        *
        * @param mode The rendering mode. Allowed values are default, viewport.
        * @return The converter object.
        */
        public HtmlToPdfClient setRenderingMode(String mode) {
            if (!mode.matches("(?i)^(default|viewport)$"))
                throw new Error(createInvalidValueMessage(mode, "setRenderingMode", "html-to-pdf", "Allowed values are default, viewport.", "set_rendering_mode"), 470);
            
            fields.put("rendering_mode", mode);
            return this;
        }

        /**
        * Specifies the scaling mode used for fitting the HTML contents to the print area.
        *
        * @param mode The smart scaling mode. Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit, single-page-fit-ex, mode1.
        * @return The converter object.
        */
        public HtmlToPdfClient setSmartScalingMode(String mode) {
            if (!mode.matches("(?i)^(default|disabled|viewport-fit|content-fit|single-page-fit|single-page-fit-ex|mode1)$"))
                throw new Error(createInvalidValueMessage(mode, "setSmartScalingMode", "html-to-pdf", "Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit, single-page-fit-ex, mode1.", "set_smart_scaling_mode"), 470);
            
            fields.put("smart_scaling_mode", mode);
            return this;
        }

        /**
        * Set the scaling factor (zoom) for the main page area.
        *
        * @param factor The percentage value. The value must be in the range 10-500.
        * @return The converter object.
        */
        public HtmlToPdfClient setScaleFactor(int factor) {
            if (!(factor >= 10 && factor <= 500))
                throw new Error(createInvalidValueMessage(factor, "setScaleFactor", "html-to-pdf", "The value must be in the range 10-500.", "set_scale_factor"), 470);
            
            fields.put("scale_factor", Integer.toString(factor));
            return this;
        }

        /**
        * Set the quality of embedded JPEG images. A lower quality results in a smaller PDF file but can lead to compression artifacts.
        *
        * @param quality The percentage value. The value must be in the range 1-100.
        * @return The converter object.
        */
        public HtmlToPdfClient setJpegQuality(int quality) {
            if (!(quality >= 1 && quality <= 100))
                throw new Error(createInvalidValueMessage(quality, "setJpegQuality", "html-to-pdf", "The value must be in the range 1-100.", "set_jpeg_quality"), 470);
            
            fields.put("jpeg_quality", Integer.toString(quality));
            return this;
        }

        /**
        * Specify which image types will be converted to JPEG. Converting lossless compression image formats (PNG, GIF, ...) to JPEG may result in a smaller PDF file.
        *
        * @param images The image category. Allowed values are none, opaque, all.
        * @return The converter object.
        */
        public HtmlToPdfClient setConvertImagesToJpeg(String images) {
            if (!images.matches("(?i)^(none|opaque|all)$"))
                throw new Error(createInvalidValueMessage(images, "setConvertImagesToJpeg", "html-to-pdf", "Allowed values are none, opaque, all.", "set_convert_images_to_jpeg"), 470);
            
            fields.put("convert_images_to_jpeg", images);
            return this;
        }

        /**
        * Set the DPI of images in PDF. A lower DPI may result in a smaller PDF file.  If the specified DPI is higher than the actual image DPI, the original image DPI is retained (no upscaling is performed). Use <span class='field-value'>0</span> to leave the images unaltered.
        *
        * @param dpi The DPI value. Must be a positive integer number or 0.
        * @return The converter object.
        */
        public HtmlToPdfClient setImageDpi(int dpi) {
            if (!(dpi >= 0))
                throw new Error(createInvalidValueMessage(dpi, "setImageDpi", "html-to-pdf", "Must be a positive integer number or 0.", "set_image_dpi"), 470);
            
            fields.put("image_dpi", Integer.toString(dpi));
            return this;
        }

        /**
        * Convert HTML forms to fillable PDF forms. Details can be found in the <a href='https://pdfcrowd.com/blog/create-fillable-pdf-form/'>blog post</a>.
        *
        * @param value Set to <span class='field-value'>true</span> to make fillable PDF forms.
        * @return The converter object.
        */
        public HtmlToPdfClient setEnablePdfForms(boolean value) {
            fields.put("enable_pdf_forms", value ? "true" : null);
            return this;
        }

        /**
        * Create linearized PDF. This is also known as Fast Web View.
        *
        * @param value Set to <span class='field-value'>true</span> to create linearized PDF.
        * @return The converter object.
        */
        public HtmlToPdfClient setLinearize(boolean value) {
            fields.put("linearize", value ? "true" : null);
            return this;
        }

        /**
        * Encrypt the PDF. This prevents search engines from indexing the contents.
        *
        * @param value Set to <span class='field-value'>true</span> to enable PDF encryption.
        * @return The converter object.
        */
        public HtmlToPdfClient setEncrypt(boolean value) {
            fields.put("encrypt", value ? "true" : null);
            return this;
        }

        /**
        * Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        *
        * @param password The user password.
        * @return The converter object.
        */
        public HtmlToPdfClient setUserPassword(String password) {
            fields.put("user_password", password);
            return this;
        }

        /**
        * Protect the PDF with an owner password.  Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        *
        * @param password The owner password.
        * @return The converter object.
        */
        public HtmlToPdfClient setOwnerPassword(String password) {
            fields.put("owner_password", password);
            return this;
        }

        /**
        * Disallow printing of the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the no-print flag in the output PDF.
        * @return The converter object.
        */
        public HtmlToPdfClient setNoPrint(boolean value) {
            fields.put("no_print", value ? "true" : null);
            return this;
        }

        /**
        * Disallow modification of the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the read-only only flag in the output PDF.
        * @return The converter object.
        */
        public HtmlToPdfClient setNoModify(boolean value) {
            fields.put("no_modify", value ? "true" : null);
            return this;
        }

        /**
        * Disallow text and graphics extraction from the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the no-copy flag in the output PDF.
        * @return The converter object.
        */
        public HtmlToPdfClient setNoCopy(boolean value) {
            fields.put("no_copy", value ? "true" : null);
            return this;
        }

        /**
        * Set the title of the PDF.
        *
        * @param title The title.
        * @return The converter object.
        */
        public HtmlToPdfClient setTitle(String title) {
            fields.put("title", title);
            return this;
        }

        /**
        * Set the subject of the PDF.
        *
        * @param subject The subject.
        * @return The converter object.
        */
        public HtmlToPdfClient setSubject(String subject) {
            fields.put("subject", subject);
            return this;
        }

        /**
        * Set the author of the PDF.
        *
        * @param author The author.
        * @return The converter object.
        */
        public HtmlToPdfClient setAuthor(String author) {
            fields.put("author", author);
            return this;
        }

        /**
        * Associate keywords with the document.
        *
        * @param keywords The string with the keywords.
        * @return The converter object.
        */
        public HtmlToPdfClient setKeywords(String keywords) {
            fields.put("keywords", keywords);
            return this;
        }

        /**
        * Extract meta tags (author, keywords and description) from the input HTML and use them in the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to extract meta tags.
        * @return The converter object.
        */
        public HtmlToPdfClient setExtractMetaTags(boolean value) {
            fields.put("extract_meta_tags", value ? "true" : null);
            return this;
        }

        /**
        * Specify the page layout to be used when the document is opened.
        *
        * @param layout Allowed values are single-page, one-column, two-column-left, two-column-right.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageLayout(String layout) {
            if (!layout.matches("(?i)^(single-page|one-column|two-column-left|two-column-right)$"))
                throw new Error(createInvalidValueMessage(layout, "setPageLayout", "html-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            
            fields.put("page_layout", layout);
            return this;
        }

        /**
        * Specify how the document should be displayed when opened.
        *
        * @param mode Allowed values are full-screen, thumbnails, outlines.
        * @return The converter object.
        */
        public HtmlToPdfClient setPageMode(String mode) {
            if (!mode.matches("(?i)^(full-screen|thumbnails|outlines)$"))
                throw new Error(createInvalidValueMessage(mode, "setPageMode", "html-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            
            fields.put("page_mode", mode);
            return this;
        }

        /**
        * Specify how the page should be displayed when opened.
        *
        * @param zoomType Allowed values are fit-width, fit-height, fit-page.
        * @return The converter object.
        */
        public HtmlToPdfClient setInitialZoomType(String zoomType) {
            if (!zoomType.matches("(?i)^(fit-width|fit-height|fit-page)$"))
                throw new Error(createInvalidValueMessage(zoomType, "setInitialZoomType", "html-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            
            fields.put("initial_zoom_type", zoomType);
            return this;
        }

        /**
        * Display the specified page when the document is opened.
        *
        * @param page Must be a positive integer number.
        * @return The converter object.
        */
        public HtmlToPdfClient setInitialPage(int page) {
            if (!(page > 0))
                throw new Error(createInvalidValueMessage(page, "setInitialPage", "html-to-pdf", "Must be a positive integer number.", "set_initial_page"), 470);
            
            fields.put("initial_page", Integer.toString(page));
            return this;
        }

        /**
        * Specify the initial page zoom in percents when the document is opened.
        *
        * @param zoom Must be a positive integer number.
        * @return The converter object.
        */
        public HtmlToPdfClient setInitialZoom(int zoom) {
            if (!(zoom > 0))
                throw new Error(createInvalidValueMessage(zoom, "setInitialZoom", "html-to-pdf", "Must be a positive integer number.", "set_initial_zoom"), 470);
            
            fields.put("initial_zoom", Integer.toString(zoom));
            return this;
        }

        /**
        * Specify whether to hide the viewer application's tool bars when the document is active.
        *
        * @param value Set to <span class='field-value'>true</span> to hide tool bars.
        * @return The converter object.
        */
        public HtmlToPdfClient setHideToolbar(boolean value) {
            fields.put("hide_toolbar", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to hide the viewer application's menu bar when the document is active.
        *
        * @param value Set to <span class='field-value'>true</span> to hide the menu bar.
        * @return The converter object.
        */
        public HtmlToPdfClient setHideMenubar(boolean value) {
            fields.put("hide_menubar", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
        *
        * @param value Set to <span class='field-value'>true</span> to hide ui elements.
        * @return The converter object.
        */
        public HtmlToPdfClient setHideWindowUi(boolean value) {
            fields.put("hide_window_ui", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to resize the document's window to fit the size of the first displayed page.
        *
        * @param value Set to <span class='field-value'>true</span> to resize the window.
        * @return The converter object.
        */
        public HtmlToPdfClient setFitWindow(boolean value) {
            fields.put("fit_window", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to position the document's window in the center of the screen.
        *
        * @param value Set to <span class='field-value'>true</span> to center the window.
        * @return The converter object.
        */
        public HtmlToPdfClient setCenterWindow(boolean value) {
            fields.put("center_window", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
        *
        * @param value Set to <span class='field-value'>true</span> to display the title.
        * @return The converter object.
        */
        public HtmlToPdfClient setDisplayTitle(boolean value) {
            fields.put("display_title", value ? "true" : null);
            return this;
        }

        /**
        * Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
        *
        * @param value Set to <span class='field-value'>true</span> to set right-to-left reading order.
        * @return The converter object.
        */
        public HtmlToPdfClient setRightToLeft(boolean value) {
            fields.put("right_to_left", value ? "true" : null);
            return this;
        }

        /**
        * Set the input data for template rendering. The data format can be JSON, XML, YAML or CSV.
        *
        * @param dataString The input data string.
        * @return The converter object.
        */
        public HtmlToPdfClient setDataString(String dataString) {
            fields.put("data_string", dataString);
            return this;
        }

        /**
        * Load the input data for template rendering from the specified file. The data format can be JSON, XML, YAML or CSV.
        *
        * @param dataFile The file path to a local file containing the input data.
        * @return The converter object.
        */
        public HtmlToPdfClient setDataFile(String dataFile) {
            files.put("data_file", dataFile);
            return this;
        }

        /**
        * Specify the input data format.
        *
        * @param dataFormat The data format. Allowed values are auto, json, xml, yaml, csv.
        * @return The converter object.
        */
        public HtmlToPdfClient setDataFormat(String dataFormat) {
            if (!dataFormat.matches("(?i)^(auto|json|xml|yaml|csv)$"))
                throw new Error(createInvalidValueMessage(dataFormat, "setDataFormat", "html-to-pdf", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            
            fields.put("data_format", dataFormat);
            return this;
        }

        /**
        * Set the encoding of the data file set by <a href='#set_data_file'>setDataFile</a>.
        *
        * @param encoding The data file encoding.
        * @return The converter object.
        */
        public HtmlToPdfClient setDataEncoding(String encoding) {
            fields.put("data_encoding", encoding);
            return this;
        }

        /**
        * Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use <span class='field-value text-nowrap'>&#x007b;&#x0025; if variable is defined &#x0025;&#x007d;</span> to check if the variable is defined.
        *
        * @param value Set to <span class='field-value'>true</span> to ignore undefined variables.
        * @return The converter object.
        */
        public HtmlToPdfClient setDataIgnoreUndefined(boolean value) {
            fields.put("data_ignore_undefined", value ? "true" : null);
            return this;
        }

        /**
        * Auto escape HTML symbols in the input data before placing them into the output.
        *
        * @param value Set to <span class='field-value'>true</span> to turn auto escaping on.
        * @return The converter object.
        */
        public HtmlToPdfClient setDataAutoEscape(boolean value) {
            fields.put("data_auto_escape", value ? "true" : null);
            return this;
        }

        /**
        * Auto trim whitespace around each template command block.
        *
        * @param value Set to <span class='field-value'>true</span> to turn auto trimming on.
        * @return The converter object.
        */
        public HtmlToPdfClient setDataTrimBlocks(boolean value) {
            fields.put("data_trim_blocks", value ? "true" : null);
            return this;
        }

        /**
        * Set the advanced data options:<ul><li><span class='field-value'>csv_delimiter</span> - The CSV data delimiter, the default is <span class='field-value'>,</span>.</li><li><span class='field-value'>xml_remove_root</span> - Remove the root XML element from the input data.</li><li><span class='field-value'>data_root</span> - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is <span class='field-value'>data</span>.</li></ul>
        *
        * @param options Comma separated list of options.
        * @return The converter object.
        */
        public HtmlToPdfClient setDataOptions(String options) {
            fields.put("data_options", options);
            return this;
        }

        /**
        * Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the <a href='#get_debug_log_url'>getDebugLogUrl</a> method or available in <a href='/user/account/log/conversion/'>conversion statistics</a>.
        *
        * @param value Set to <span class='field-value'>true</span> to enable the debug logging.
        * @return The converter object.
        */
        public HtmlToPdfClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
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
        * This method can only be called after a call to one of the convertXtoY methods.
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
        * Get the number of pages in the output document.
        * @return The page count.
        */
        public int getPageCount() {
            return helper.getPageCount();
        }

        /**
        * Get the total number of pages in the original output document, including the pages excluded by <a href='#set_print_page_range'>setPrintPageRange()</a>.
        * @return The total page count.
        */
        public int getTotalPageCount() {
            return helper.getTotalPageCount();
        }

        /**
        * Get the size of the output in bytes.
        * @return The count of bytes.
        */
        public int getOutputSize() {
            return helper.getOutputSize();
        }

        /**
        * Get the version details.
        * @return API version, converter version, and client version.
        */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
        * Tag the conversion with a custom value. The tag is used in <a href='/user/account/log/conversion/'>conversion statistics</a>. A value longer than 32 characters is cut off.
        *
        * @param tag A string with the custom tag.
        * @return The converter object.
        */
        public HtmlToPdfClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public HtmlToPdfClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public HtmlToPdfClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
        * A client certificate to authenticate Pdfcrowd converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
        *
        * @param certificate The file must be in PKCS12 format. The file must exist and not be empty.
        * @return The converter object.
        */
        public HtmlToPdfClient setClientCertificate(String certificate) {
            if (!(new File(certificate).length() > 0))
                throw new Error(createInvalidValueMessage(certificate, "setClientCertificate", "html-to-pdf", "The file must exist and not be empty.", "set_client_certificate"), 470);
            
            files.put("client_certificate", certificate);
            return this;
        }

        /**
        * A password for PKCS12 file with a client certificate if it is needed.
        *
        * @param password
        * @return The converter object.
        */
        public HtmlToPdfClient setClientCertificatePassword(String password) {
            fields.put("client_certificate_password", password);
            return this;
        }

        /**
        * Set the internal DPI resolution used for positioning of PDF contents. It can help in situations when there are small inaccuracies in the PDF. It is recommended to use values that are a multiple of 72, such as 288 or 360.
        *
        * @param dpi The DPI value. The value must be in the range of 72-600.
        * @return The converter object.
        */
        public HtmlToPdfClient setLayoutDpi(int dpi) {
            if (!(dpi >= 72 && dpi <= 600))
                throw new Error(createInvalidValueMessage(dpi, "setLayoutDpi", "html-to-pdf", "The value must be in the range of 72-600.", "set_layout_dpi"), 470);
            
            fields.put("layout_dpi", Integer.toString(dpi));
            return this;
        }

        /**
        * A 2D transformation matrix applied to the main contents on each page. The origin [0,0] is located at the top-left corner of the contents. The resolution is 72 dpi.
        *
        * @param matrix A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
        * @return The converter object.
        */
        public HtmlToPdfClient setContentsMatrix(String matrix) {
            fields.put("contents_matrix", matrix);
            return this;
        }

        /**
        * A 2D transformation matrix applied to the page header contents. The origin [0,0] is located at the top-left corner of the header. The resolution is 72 dpi.
        *
        * @param matrix A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
        * @return The converter object.
        */
        public HtmlToPdfClient setHeaderMatrix(String matrix) {
            fields.put("header_matrix", matrix);
            return this;
        }

        /**
        * A 2D transformation matrix applied to the page footer contents. The origin [0,0] is located at the top-left corner of the footer. The resolution is 72 dpi.
        *
        * @param matrix A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
        * @return The converter object.
        */
        public HtmlToPdfClient setFooterMatrix(String matrix) {
            fields.put("footer_matrix", matrix);
            return this;
        }

        /**
        * Disable automatic height adjustment that compensates for pixel to point rounding errors.
        *
        * @param value Set to <span class='field-value'>true</span> to disable automatic height scale.
        * @return The converter object.
        */
        public HtmlToPdfClient setDisablePageHeightOptimization(boolean value) {
            fields.put("disable_page_height_optimization", value ? "true" : null);
            return this;
        }

        /**
        * Add special CSS classes to the main document's body element. This allows applying custom styling based on these classes:
  <ul>
    <li><span class='field-value'>pdfcrowd-page-X</span> - where X is the current page number</li>
    <li><span class='field-value'>pdfcrowd-page-odd</span> - odd page</li>
    <li><span class='field-value'>pdfcrowd-page-even</span> - even page</li>
  </ul>
        * Warning: If your custom styling affects the contents area size (e.g. by using different margins, padding, border width), the resulting PDF may contain duplicit contents or some contents may be missing.
        *
        * @param value Set to <span class='field-value'>true</span> to add the special CSS classes.
        * @return The converter object.
        */
        public HtmlToPdfClient setMainDocumentCssAnnotation(boolean value) {
            fields.put("main_document_css_annotation", value ? "true" : null);
            return this;
        }

        /**
        * Add special CSS classes to the header/footer's body element. This allows applying custom styling based on these classes:
  <ul>
    <li><span class='field-value'>pdfcrowd-page-X</span> - where X is the current page number</li>
    <li><span class='field-value'>pdfcrowd-page-count-X</span> - where X is the total page count</li>
    <li><span class='field-value'>pdfcrowd-page-first</span> - the first page</li>
    <li><span class='field-value'>pdfcrowd-page-last</span> - the last page</li>
    <li><span class='field-value'>pdfcrowd-page-odd</span> - odd page</li>
    <li><span class='field-value'>pdfcrowd-page-even</span> - even page</li>
  </ul>
        *
        * @param value Set to <span class='field-value'>true</span> to add the special CSS classes.
        * @return The converter object.
        */
        public HtmlToPdfClient setHeaderFooterCssAnnotation(boolean value) {
            fields.put("header_footer_css_annotation", value ? "true" : null);
            return this;
        }

        /**
        * Set the maximum time to load the page and its resources. After this time, all requests will be considered successful. This can be useful to ensure that the conversion does not timeout. Use this method if there is no other way to fix page loading.
        *
        * @param maxTime The number of seconds to wait. The value must be in the range 10-30.
        * @return The converter object.
        */
        public HtmlToPdfClient setMaxLoadingTime(int maxTime) {
            if (!(maxTime >= 10 && maxTime <= 30))
                throw new Error(createInvalidValueMessage(maxTime, "setMaxLoadingTime", "html-to-pdf", "The value must be in the range 10-30.", "set_max_loading_time"), 470);
            
            fields.put("max_loading_time", Integer.toString(maxTime));
            return this;
        }

        /**
        * Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        *
        * @param version The version identifier. Allowed values are latest, 20.10, 18.10.
        * @return The converter object.
        */
        public HtmlToPdfClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(latest|20.10|18.10)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "html-to-pdf", "Allowed values are latest, 20.10, 18.10.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        *
        * @param value Set to <span class='field-value'>true</span> to use HTTP.
        * @return The converter object.
        */
        public HtmlToPdfClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
        * Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        *
        * @param agent The user agent string.
        * @return The converter object.
        */
        public HtmlToPdfClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        *
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        * @return The converter object.
        */
        public HtmlToPdfClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
        * Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        *
        * @param count Number of retries.
        * @return The converter object.
        */
        public HtmlToPdfClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
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
        * @return The converter object.
        */
        public HtmlToImageClient setOutputFormat(String outputFormat) {
            if (!outputFormat.matches("(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$"))
                throw new Error(createInvalidValueMessage(outputFormat, "setOutputFormat", "html-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            
            fields.put("output_format", outputFormat);
            return this;
        }

        /**
        * Convert a web page.
        *
        * @param url The address of the web page to convert. The supported protocols are http:// and https://.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "html-to-image", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
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
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "html-to-image", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
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
        * Convert a local file.
        *
        * @param file The path to a local file to convert.<br> The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip).<br> If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            
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
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
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
        * Convert a string.
        *
        * @param text The string content to convert. The string must not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertString(String text) {
            if (!(text != null && !text.isEmpty()))
                throw new Error(createInvalidValueMessage(text, "convertString", "html-to-image", "The string must not be empty.", "convert_string"), 470);
            
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
                throw new Error(createInvalidValueMessage(text, "convertStringToStream::text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470);
            
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
        * Convert the contents of an input stream.
        *
        * @param inStream The input stream with source data.<br> The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).<br>The archive can contain HTML code and its external assets (images, style sheets, javascript).
        * @return Byte array containing the conversion output.
        */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert the contents of an input stream and write the result to an output stream.
        *
        * @param inStream The input stream with source data.<br> The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).<br>The archive can contain HTML code and its external assets (images, style sheets, javascript).
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert the contents of an input stream and write the result to a local file.
        *
        * @param inStream The input stream with source data.<br> The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).<br>The archive can contain HTML code and its external assets (images, style sheets, javascript).
        * @param filePath The output file path. The string must not be empty.
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
        * Set the file name of the main HTML document stored in the input archive. If not specified, the first HTML file in the archive is used for conversion. Use this method if the input archive contains multiple HTML documents.
        *
        * @param filename The file name.
        * @return The converter object.
        */
        public HtmlToImageClient setZipMainFilename(String filename) {
            fields.put("zip_main_filename", filename);
            return this;
        }

        /**
        * Set the output image width in pixels.
        *
        * @param width The value must be in the range 96-65000.
        * @return The converter object.
        */
        public HtmlToImageClient setScreenshotWidth(int width) {
            if (!(width >= 96 && width <= 65000))
                throw new Error(createInvalidValueMessage(width, "setScreenshotWidth", "html-to-image", "The value must be in the range 96-65000.", "set_screenshot_width"), 470);
            
            fields.put("screenshot_width", Integer.toString(width));
            return this;
        }

        /**
        * Set the output image height in pixels. If it is not specified, actual document height is used.
        *
        * @param height Must be a positive integer number.
        * @return The converter object.
        */
        public HtmlToImageClient setScreenshotHeight(int height) {
            if (!(height > 0))
                throw new Error(createInvalidValueMessage(height, "setScreenshotHeight", "html-to-image", "Must be a positive integer number.", "set_screenshot_height"), 470);
            
            fields.put("screenshot_height", Integer.toString(height));
            return this;
        }

        /**
        * Set the scaling factor (zoom) for the output image.
        *
        * @param factor The percentage value. Must be a positive integer number.
        * @return The converter object.
        */
        public HtmlToImageClient setScaleFactor(int factor) {
            if (!(factor > 0))
                throw new Error(createInvalidValueMessage(factor, "setScaleFactor", "html-to-image", "Must be a positive integer number.", "set_scale_factor"), 470);
            
            fields.put("scale_factor", Integer.toString(factor));
            return this;
        }

        /**
        * The output image background color.
        *
        * @param color The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        * @return The converter object.
        */
        public HtmlToImageClient setBackgroundColor(String color) {
            if (!color.matches("^[0-9a-fA-F]{6,8}$"))
                throw new Error(createInvalidValueMessage(color, "setBackgroundColor", "html-to-image", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_background_color"), 470);
            
            fields.put("background_color", color);
            return this;
        }

        /**
        * Use the print version of the page if available (@media print).
        *
        * @param value Set to <span class='field-value'>true</span> to use the print version of the page.
        * @return The converter object.
        */
        public HtmlToImageClient setUsePrintMedia(boolean value) {
            fields.put("use_print_media", value ? "true" : null);
            return this;
        }

        /**
        * Do not print the background graphics.
        *
        * @param value Set to <span class='field-value'>true</span> to disable the background graphics.
        * @return The converter object.
        */
        public HtmlToImageClient setNoBackground(boolean value) {
            fields.put("no_background", value ? "true" : null);
            return this;
        }

        /**
        * Do not execute JavaScript.
        *
        * @param value Set to <span class='field-value'>true</span> to disable JavaScript in web pages.
        * @return The converter object.
        */
        public HtmlToImageClient setDisableJavascript(boolean value) {
            fields.put("disable_javascript", value ? "true" : null);
            return this;
        }

        /**
        * Do not load images.
        *
        * @param value Set to <span class='field-value'>true</span> to disable loading of images.
        * @return The converter object.
        */
        public HtmlToImageClient setDisableImageLoading(boolean value) {
            fields.put("disable_image_loading", value ? "true" : null);
            return this;
        }

        /**
        * Disable loading fonts from remote sources.
        *
        * @param value Set to <span class='field-value'>true</span> disable loading remote fonts.
        * @return The converter object.
        */
        public HtmlToImageClient setDisableRemoteFonts(boolean value) {
            fields.put("disable_remote_fonts", value ? "true" : null);
            return this;
        }

        /**
        * Use a mobile user agent.
        *
        * @param value Set to <span class='field-value'>true</span> to use a mobile user agent.
        * @return The converter object.
        */
        public HtmlToImageClient setUseMobileUserAgent(boolean value) {
            fields.put("use_mobile_user_agent", value ? "true" : null);
            return this;
        }

        /**
        * Specifies how iframes are handled.
        *
        * @param iframes Allowed values are all, same-origin, none.
        * @return The converter object.
        */
        public HtmlToImageClient setLoadIframes(String iframes) {
            if (!iframes.matches("(?i)^(all|same-origin|none)$"))
                throw new Error(createInvalidValueMessage(iframes, "setLoadIframes", "html-to-image", "Allowed values are all, same-origin, none.", "set_load_iframes"), 470);
            
            fields.put("load_iframes", iframes);
            return this;
        }

        /**
        * Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
        *
        * @param value Set to <span class='field-value'>true</span> to block ads in web pages.
        * @return The converter object.
        */
        public HtmlToImageClient setBlockAds(boolean value) {
            fields.put("block_ads", value ? "true" : null);
            return this;
        }

        /**
        * Set the default HTML content text encoding.
        *
        * @param encoding The text encoding of the HTML content.
        * @return The converter object.
        */
        public HtmlToImageClient setDefaultEncoding(String encoding) {
            fields.put("default_encoding", encoding);
            return this;
        }

        /**
        * Set the locale for the conversion. This may affect the output format of dates, times and numbers.
        *
        * @param locale The locale code according to ISO 639.
        * @return The converter object.
        */
        public HtmlToImageClient setLocale(String locale) {
            fields.put("locale", locale);
            return this;
        }

        /**
        * Set the HTTP authentication user name.
        *
        * @param userName The user name.
        * @return The converter object.
        */
        public HtmlToImageClient setHttpAuthUserName(String userName) {
            fields.put("http_auth_user_name", userName);
            return this;
        }

        /**
        * Set the HTTP authentication password.
        *
        * @param password The password.
        * @return The converter object.
        */
        public HtmlToImageClient setHttpAuthPassword(String password) {
            fields.put("http_auth_password", password);
            return this;
        }

        /**
        * Set credentials to access HTTP base authentication protected websites.
        *
        * @param userName Set the HTTP authentication user name.
        * @param password Set the HTTP authentication password.
        * @return The converter object.
        */
        public HtmlToImageClient setHttpAuth(String userName, String password) {
            this.setHttpAuthUserName(userName);
            this.setHttpAuthPassword(password);
            return this;
        }

        /**
        * Set cookies that are sent in Pdfcrowd HTTP requests.
        *
        * @param cookies The cookie string.
        * @return The converter object.
        */
        public HtmlToImageClient setCookies(String cookies) {
            fields.put("cookies", cookies);
            return this;
        }

        /**
        * Do not allow insecure HTTPS connections.
        *
        * @param value Set to <span class='field-value'>true</span> to enable SSL certificate verification.
        * @return The converter object.
        */
        public HtmlToImageClient setVerifySslCertificates(boolean value) {
            fields.put("verify_ssl_certificates", value ? "true" : null);
            return this;
        }

        /**
        * Abort the conversion if the main URL HTTP status code is greater than or equal to 400.
        *
        * @param failOnError Set to <span class='field-value'>true</span> to abort the conversion.
        * @return The converter object.
        */
        public HtmlToImageClient setFailOnMainUrlError(boolean failOnError) {
            fields.put("fail_on_main_url_error", failOnError ? "true" : null);
            return this;
        }

        /**
        * Abort the conversion if any of the sub-request HTTP status code is greater than or equal to 400 or if some sub-requests are still pending. See details in a debug log.
        *
        * @param failOnError Set to <span class='field-value'>true</span> to abort the conversion.
        * @return The converter object.
        */
        public HtmlToImageClient setFailOnAnyUrlError(boolean failOnError) {
            fields.put("fail_on_any_url_error", failOnError ? "true" : null);
            return this;
        }

        /**
        * Do not send the X-Pdfcrowd HTTP header in Pdfcrowd HTTP requests.
        *
        * @param value Set to <span class='field-value'>true</span> to disable sending X-Pdfcrowd HTTP header.
        * @return The converter object.
        */
        public HtmlToImageClient setNoXpdfcrowdHeader(boolean value) {
            fields.put("no_xpdfcrowd_header", value ? "true" : null);
            return this;
        }

        /**
        * Apply custom CSS to the input HTML document. It allows you to modify the visual appearance and layout of your HTML content dynamically. Tip: Using <span class='field-value'>!important</span> in custom CSS provides a way to prioritize and override conflicting styles.
        *
        * @param css A string containing valid CSS. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToImageClient setCustomCss(String css) {
            if (!(css != null && !css.isEmpty()))
                throw new Error(createInvalidValueMessage(css, "setCustomCss", "html-to-image", "The string must not be empty.", "set_custom_css"), 470);
            
            fields.put("custom_css", css);
            return this;
        }

        /**
        * Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our <a href='/api/libpdfcrowd/'>JavaScript library</a>.
        *
        * @param javascript A string containing a JavaScript code. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToImageClient setCustomJavascript(String javascript) {
            if (!(javascript != null && !javascript.isEmpty()))
                throw new Error(createInvalidValueMessage(javascript, "setCustomJavascript", "html-to-image", "The string must not be empty.", "set_custom_javascript"), 470);
            
            fields.put("custom_javascript", javascript);
            return this;
        }

        /**
        * Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our <a href='/api/libpdfcrowd/'>JavaScript library</a>.
        *
        * @param javascript A string containing a JavaScript code. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToImageClient setOnLoadJavascript(String javascript) {
            if (!(javascript != null && !javascript.isEmpty()))
                throw new Error(createInvalidValueMessage(javascript, "setOnLoadJavascript", "html-to-image", "The string must not be empty.", "set_on_load_javascript"), 470);
            
            fields.put("on_load_javascript", javascript);
            return this;
        }

        /**
        * Set a custom HTTP header that is sent in Pdfcrowd HTTP requests.
        *
        * @param header A string containing the header name and value separated by a colon.
        * @return The converter object.
        */
        public HtmlToImageClient setCustomHttpHeader(String header) {
            if (!header.matches("^.+:.+$"))
                throw new Error(createInvalidValueMessage(header, "setCustomHttpHeader", "html-to-image", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            
            fields.put("custom_http_header", header);
            return this;
        }

        /**
        * Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your API license defines the maximum wait time by "Max Delay" parameter.
        *
        * @param delay The number of milliseconds to wait. Must be a positive integer number or 0.
        * @return The converter object.
        */
        public HtmlToImageClient setJavascriptDelay(int delay) {
            if (!(delay >= 0))
                throw new Error(createInvalidValueMessage(delay, "setJavascriptDelay", "html-to-image", "Must be a positive integer number or 0.", "set_javascript_delay"), 470);
            
            fields.put("javascript_delay", Integer.toString(delay));
            return this;
        }

        /**
        * Convert only the specified element from the main document and its children. The element is specified by one or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a>. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
        *
        * @param selectors One or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a> separated by commas. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToImageClient setElementToConvert(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "setElementToConvert", "html-to-image", "The string must not be empty.", "set_element_to_convert"), 470);
            
            fields.put("element_to_convert", selectors);
            return this;
        }

        /**
        * Specify the DOM handling when only a part of the document is converted. This can affect the CSS rules used.
        *
        * @param mode Allowed values are cut-out, remove-siblings, hide-siblings.
        * @return The converter object.
        */
        public HtmlToImageClient setElementToConvertMode(String mode) {
            if (!mode.matches("(?i)^(cut-out|remove-siblings|hide-siblings)$"))
                throw new Error(createInvalidValueMessage(mode, "setElementToConvertMode", "html-to-image", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            
            fields.put("element_to_convert_mode", mode);
            return this;
        }

        /**
        * Wait for the specified element in a source document. The element is specified by one or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a>. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your API license defines the maximum wait time by "Max Delay" parameter.
        *
        * @param selectors One or more <a href='https://developer.mozilla.org/en-US/docs/Learn/CSS/Introduction_to_CSS/Selectors'>CSS selectors</a> separated by commas. The string must not be empty.
        * @return The converter object.
        */
        public HtmlToImageClient setWaitForElement(String selectors) {
            if (!(selectors != null && !selectors.isEmpty()))
                throw new Error(createInvalidValueMessage(selectors, "setWaitForElement", "html-to-image", "The string must not be empty.", "set_wait_for_element"), 470);
            
            fields.put("wait_for_element", selectors);
            return this;
        }

        /**
        * The main HTML element for conversion is detected automatically.
        *
        * @param value Set to <span class='field-value'>true</span> to detect the main element.
        * @return The converter object.
        */
        public HtmlToImageClient setAutoDetectElementToConvert(boolean value) {
            fields.put("auto_detect_element_to_convert", value ? "true" : null);
            return this;
        }

        /**
        * The input HTML is automatically enhanced to improve the readability.
        *
        * @param enhancements Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.
        * @return The converter object.
        */
        public HtmlToImageClient setReadabilityEnhancements(String enhancements) {
            if (!enhancements.matches("(?i)^(none|readability-v1|readability-v2|readability-v3|readability-v4)$"))
                throw new Error(createInvalidValueMessage(enhancements, "setReadabilityEnhancements", "html-to-image", "Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.", "set_readability_enhancements"), 470);
            
            fields.put("readability_enhancements", enhancements);
            return this;
        }

        /**
        * Set the input data for template rendering. The data format can be JSON, XML, YAML or CSV.
        *
        * @param dataString The input data string.
        * @return The converter object.
        */
        public HtmlToImageClient setDataString(String dataString) {
            fields.put("data_string", dataString);
            return this;
        }

        /**
        * Load the input data for template rendering from the specified file. The data format can be JSON, XML, YAML or CSV.
        *
        * @param dataFile The file path to a local file containing the input data.
        * @return The converter object.
        */
        public HtmlToImageClient setDataFile(String dataFile) {
            files.put("data_file", dataFile);
            return this;
        }

        /**
        * Specify the input data format.
        *
        * @param dataFormat The data format. Allowed values are auto, json, xml, yaml, csv.
        * @return The converter object.
        */
        public HtmlToImageClient setDataFormat(String dataFormat) {
            if (!dataFormat.matches("(?i)^(auto|json|xml|yaml|csv)$"))
                throw new Error(createInvalidValueMessage(dataFormat, "setDataFormat", "html-to-image", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            
            fields.put("data_format", dataFormat);
            return this;
        }

        /**
        * Set the encoding of the data file set by <a href='#set_data_file'>setDataFile</a>.
        *
        * @param encoding The data file encoding.
        * @return The converter object.
        */
        public HtmlToImageClient setDataEncoding(String encoding) {
            fields.put("data_encoding", encoding);
            return this;
        }

        /**
        * Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use <span class='field-value text-nowrap'>&#x007b;&#x0025; if variable is defined &#x0025;&#x007d;</span> to check if the variable is defined.
        *
        * @param value Set to <span class='field-value'>true</span> to ignore undefined variables.
        * @return The converter object.
        */
        public HtmlToImageClient setDataIgnoreUndefined(boolean value) {
            fields.put("data_ignore_undefined", value ? "true" : null);
            return this;
        }

        /**
        * Auto escape HTML symbols in the input data before placing them into the output.
        *
        * @param value Set to <span class='field-value'>true</span> to turn auto escaping on.
        * @return The converter object.
        */
        public HtmlToImageClient setDataAutoEscape(boolean value) {
            fields.put("data_auto_escape", value ? "true" : null);
            return this;
        }

        /**
        * Auto trim whitespace around each template command block.
        *
        * @param value Set to <span class='field-value'>true</span> to turn auto trimming on.
        * @return The converter object.
        */
        public HtmlToImageClient setDataTrimBlocks(boolean value) {
            fields.put("data_trim_blocks", value ? "true" : null);
            return this;
        }

        /**
        * Set the advanced data options:<ul><li><span class='field-value'>csv_delimiter</span> - The CSV data delimiter, the default is <span class='field-value'>,</span>.</li><li><span class='field-value'>xml_remove_root</span> - Remove the root XML element from the input data.</li><li><span class='field-value'>data_root</span> - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is <span class='field-value'>data</span>.</li></ul>
        *
        * @param options Comma separated list of options.
        * @return The converter object.
        */
        public HtmlToImageClient setDataOptions(String options) {
            fields.put("data_options", options);
            return this;
        }

        /**
        * Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the <a href='#get_debug_log_url'>getDebugLogUrl</a> method or available in <a href='/user/account/log/conversion/'>conversion statistics</a>.
        *
        * @param value Set to <span class='field-value'>true</span> to enable the debug logging.
        * @return The converter object.
        */
        public HtmlToImageClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
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
        * This method can only be called after a call to one of the convertXtoY methods.
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
        * Get the version details.
        * @return API version, converter version, and client version.
        */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
        * Tag the conversion with a custom value. The tag is used in <a href='/user/account/log/conversion/'>conversion statistics</a>. A value longer than 32 characters is cut off.
        *
        * @param tag A string with the custom tag.
        * @return The converter object.
        */
        public HtmlToImageClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public HtmlToImageClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public HtmlToImageClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
        * A client certificate to authenticate Pdfcrowd converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
        *
        * @param certificate The file must be in PKCS12 format. The file must exist and not be empty.
        * @return The converter object.
        */
        public HtmlToImageClient setClientCertificate(String certificate) {
            if (!(new File(certificate).length() > 0))
                throw new Error(createInvalidValueMessage(certificate, "setClientCertificate", "html-to-image", "The file must exist and not be empty.", "set_client_certificate"), 470);
            
            files.put("client_certificate", certificate);
            return this;
        }

        /**
        * A password for PKCS12 file with a client certificate if it is needed.
        *
        * @param password
        * @return The converter object.
        */
        public HtmlToImageClient setClientCertificatePassword(String password) {
            fields.put("client_certificate_password", password);
            return this;
        }

        /**
        * Set the maximum time to load the page and its resources. After this time, all requests will be considered successful. This can be useful to ensure that the conversion does not timeout. Use this method if there is no other way to fix page loading.
        *
        * @param maxTime The number of seconds to wait. The value must be in the range 10-30.
        * @return The converter object.
        */
        public HtmlToImageClient setMaxLoadingTime(int maxTime) {
            if (!(maxTime >= 10 && maxTime <= 30))
                throw new Error(createInvalidValueMessage(maxTime, "setMaxLoadingTime", "html-to-image", "The value must be in the range 10-30.", "set_max_loading_time"), 470);
            
            fields.put("max_loading_time", Integer.toString(maxTime));
            return this;
        }

        /**
        * Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        *
        * @param version The version identifier. Allowed values are latest, 20.10, 18.10.
        * @return The converter object.
        */
        public HtmlToImageClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(latest|20.10|18.10)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "html-to-image", "Allowed values are latest, 20.10, 18.10.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        *
        * @param value Set to <span class='field-value'>true</span> to use HTTP.
        * @return The converter object.
        */
        public HtmlToImageClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
        * Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        *
        * @param agent The user agent string.
        * @return The converter object.
        */
        public HtmlToImageClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        *
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        * @return The converter object.
        */
        public HtmlToImageClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
        * Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        *
        * @param count Number of retries.
        * @return The converter object.
        */
        public HtmlToImageClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
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
                throw new Error(createInvalidValueMessage(url, "convertUrl", "image-to-image", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
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
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "image-to-image", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
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
        * Convert a local file.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a local file and write the result to an output stream.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a local file and write the result to a local file.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @param filePath The output file path. The string must not be empty.
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
        * Convert the contents of an input stream.
        *
        * @param inStream The input stream with source data.<br>
        * @return Byte array containing the conversion output.
        */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert the contents of an input stream and write the result to an output stream.
        *
        * @param inStream The input stream with source data.<br>
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert the contents of an input stream and write the result to a local file.
        *
        * @param inStream The input stream with source data.<br>
        * @param filePath The output file path. The string must not be empty.
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
        * The format of the output file.
        *
        * @param outputFormat Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
        * @return The converter object.
        */
        public ImageToImageClient setOutputFormat(String outputFormat) {
            if (!outputFormat.matches("(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$"))
                throw new Error(createInvalidValueMessage(outputFormat, "setOutputFormat", "image-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            
            fields.put("output_format", outputFormat);
            return this;
        }

        /**
        * Resize the image.
        *
        * @param resize The resize percentage or new image dimensions.
        * @return The converter object.
        */
        public ImageToImageClient setResize(String resize) {
            fields.put("resize", resize);
            return this;
        }

        /**
        * Rotate the image.
        *
        * @param rotate The rotation specified in degrees.
        * @return The converter object.
        */
        public ImageToImageClient setRotate(String rotate) {
            fields.put("rotate", rotate);
            return this;
        }

        /**
        * Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
        *
        * @param x The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setCropAreaX(String x) {
            if (!x.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(x, "setCropAreaX", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_crop_area_x"), 470);
            
            fields.put("crop_area_x", x);
            return this;
        }

        /**
        * Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
        *
        * @param y The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setCropAreaY(String y) {
            if (!y.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(y, "setCropAreaY", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_crop_area_y"), 470);
            
            fields.put("crop_area_y", y);
            return this;
        }

        /**
        * Set the width of the content area. It should be at least 1 inch.
        *
        * @param width The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setCropAreaWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setCropAreaWidth", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_crop_area_width"), 470);
            
            fields.put("crop_area_width", width);
            return this;
        }

        /**
        * Set the height of the content area. It should be at least 1 inch.
        *
        * @param height The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setCropAreaHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setCropAreaHeight", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_crop_area_height"), 470);
            
            fields.put("crop_area_height", height);
            return this;
        }

        /**
        * Set the content area position and size. The content area enables to specify the part to be converted.
        *
        * @param x Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param y Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param width Set the width of the content area. It should be at least 1 inch. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param height Set the height of the content area. It should be at least 1 inch. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setCropArea(String x, String y, String width, String height) {
            this.setCropAreaX(x);
            this.setCropAreaY(y);
            this.setCropAreaWidth(width);
            this.setCropAreaHeight(height);
            return this;
        }

        /**
        * Remove borders of an image which does not change in color.
        *
        * @param value Set to <span class='field-value'>true</span> to remove borders.
        * @return The converter object.
        */
        public ImageToImageClient setRemoveBorders(boolean value) {
            fields.put("remove_borders", value ? "true" : null);
            return this;
        }

        /**
        * Set the output canvas size.
        *
        * @param size Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
        * @return The converter object.
        */
        public ImageToImageClient setCanvasSize(String size) {
            if (!size.matches("(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$"))
                throw new Error(createInvalidValueMessage(size, "setCanvasSize", "image-to-image", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_canvas_size"), 470);
            
            fields.put("canvas_size", size);
            return this;
        }

        /**
        * Set the output canvas width.
        *
        * @param width The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setCanvasWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setCanvasWidth", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_canvas_width"), 470);
            
            fields.put("canvas_width", width);
            return this;
        }

        /**
        * Set the output canvas height.
        *
        * @param height The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setCanvasHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setCanvasHeight", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_canvas_height"), 470);
            
            fields.put("canvas_height", height);
            return this;
        }

        /**
        * Set the output canvas dimensions. If no canvas size is specified, margins are applied as a border around the image.
        *
        * @param width Set the output canvas width. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param height Set the output canvas height. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setCanvasDimensions(String width, String height) {
            this.setCanvasWidth(width);
            this.setCanvasHeight(height);
            return this;
        }

        /**
        * Set the output canvas orientation.
        *
        * @param orientation Allowed values are landscape, portrait.
        * @return The converter object.
        */
        public ImageToImageClient setOrientation(String orientation) {
            if (!orientation.matches("(?i)^(landscape|portrait)$"))
                throw new Error(createInvalidValueMessage(orientation, "setOrientation", "image-to-image", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            
            fields.put("orientation", orientation);
            return this;
        }

        /**
        * Set the image position on the canvas.
        *
        * @param position Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.
        * @return The converter object.
        */
        public ImageToImageClient setPosition(String position) {
            if (!position.matches("(?i)^(center|top|bottom|left|right|top-left|top-right|bottom-left|bottom-right)$"))
                throw new Error(createInvalidValueMessage(position, "setPosition", "image-to-image", "Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.", "set_position"), 470);
            
            fields.put("position", position);
            return this;
        }

        /**
        * Set the mode to print the image on the canvas.
        *
        * @param mode Allowed values are default, fit, stretch.
        * @return The converter object.
        */
        public ImageToImageClient setPrintCanvasMode(String mode) {
            if (!mode.matches("(?i)^(default|fit|stretch)$"))
                throw new Error(createInvalidValueMessage(mode, "setPrintCanvasMode", "image-to-image", "Allowed values are default, fit, stretch.", "set_print_canvas_mode"), 470);
            
            fields.put("print_canvas_mode", mode);
            return this;
        }

        /**
        * Set the output canvas top margin.
        *
        * @param top The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setMarginTop(String top) {
            if (!top.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(top, "setMarginTop", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_top"), 470);
            
            fields.put("margin_top", top);
            return this;
        }

        /**
        * Set the output canvas right margin.
        *
        * @param right The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setMarginRight(String right) {
            if (!right.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(right, "setMarginRight", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_right"), 470);
            
            fields.put("margin_right", right);
            return this;
        }

        /**
        * Set the output canvas bottom margin.
        *
        * @param bottom The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setMarginBottom(String bottom) {
            if (!bottom.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(bottom, "setMarginBottom", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_bottom"), 470);
            
            fields.put("margin_bottom", bottom);
            return this;
        }

        /**
        * Set the output canvas left margin.
        *
        * @param left The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setMarginLeft(String left) {
            if (!left.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(left, "setMarginLeft", "image-to-image", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_left"), 470);
            
            fields.put("margin_left", left);
            return this;
        }

        /**
        * Set the output canvas margins.
        *
        * @param top Set the output canvas top margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param right Set the output canvas right margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param bottom Set the output canvas bottom margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param left Set the output canvas left margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToImageClient setMargins(String top, String right, String bottom, String left) {
            this.setMarginTop(top);
            this.setMarginRight(right);
            this.setMarginBottom(bottom);
            this.setMarginLeft(left);
            return this;
        }

        /**
        * The canvas background color in RGB or RGBA hexadecimal format. The color fills the entire canvas regardless of margins. If no canvas size is specified and the image format supports background (e.g. PDF, PNG), the background color is applied too.
        *
        * @param color The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        * @return The converter object.
        */
        public ImageToImageClient setCanvasBackgroundColor(String color) {
            if (!color.matches("^[0-9a-fA-F]{6,8}$"))
                throw new Error(createInvalidValueMessage(color, "setCanvasBackgroundColor", "image-to-image", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_canvas_background_color"), 470);
            
            fields.put("canvas_background_color", color);
            return this;
        }

        /**
        * Set the DPI resolution of the input image. The DPI affects margin options specified in points too (e.g. 1 point is equal to 1 pixel in 96 DPI).
        *
        * @param dpi The DPI value.
        * @return The converter object.
        */
        public ImageToImageClient setDpi(int dpi) {
            fields.put("dpi", Integer.toString(dpi));
            return this;
        }

        /**
        * Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the <a href='#get_debug_log_url'>getDebugLogUrl</a> method or available in <a href='/user/account/log/conversion/'>conversion statistics</a>.
        *
        * @param value Set to <span class='field-value'>true</span> to enable the debug logging.
        * @return The converter object.
        */
        public ImageToImageClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
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
        * This method can only be called after a call to one of the convertXtoY methods.
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
        * Get the version details.
        * @return API version, converter version, and client version.
        */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
        * Tag the conversion with a custom value. The tag is used in <a href='/user/account/log/conversion/'>conversion statistics</a>. A value longer than 32 characters is cut off.
        *
        * @param tag A string with the custom tag.
        * @return The converter object.
        */
        public ImageToImageClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public ImageToImageClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public ImageToImageClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
        * Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        *
        * @param version The version identifier. Allowed values are latest, 20.10, 18.10.
        * @return The converter object.
        */
        public ImageToImageClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(latest|20.10|18.10)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "image-to-image", "Allowed values are latest, 20.10, 18.10.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        *
        * @param value Set to <span class='field-value'>true</span> to use HTTP.
        * @return The converter object.
        */
        public ImageToImageClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
        * Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        *
        * @param agent The user agent string.
        * @return The converter object.
        */
        public ImageToImageClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        *
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        * @return The converter object.
        */
        public ImageToImageClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
        * Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        *
        * @param count Number of retries.
        * @return The converter object.
        */
        public ImageToImageClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
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
        * @param action Allowed values are join, shuffle, extract, delete.
        * @return The converter object.
        */
        public PdfToPdfClient setAction(String action) {
            if (!action.matches("(?i)^(join|shuffle|extract|delete)$"))
                throw new Error(createInvalidValueMessage(action, "setAction", "pdf-to-pdf", "Allowed values are join, shuffle, extract, delete.", "set_action"), 470);
            
            fields.put("action", action);
            return this;
        }

        /**
        * Perform an action on the input files.
        * @return Byte array containing the output PDF.
        */
        public byte[] convert() {
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Perform an action on the input files and write the output PDF to an output stream.
        *
        * @param outStream The output stream that will contain the output PDF.
        */
        public void convertToStream(OutputStream outStream) {
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Perform an action on the input files and write the output PDF to a file.
        *
        * @param filePath The output file path. The string must not be empty.
        */
        public void convertToFile(String filePath) throws IOException {
            if (!(filePath != null && !filePath.isEmpty()))
                throw new Error(createInvalidValueMessage(filePath, "convertToFile", "pdf-to-pdf", "The string must not be empty.", "convert_to_file"), 470);
            
            FileOutputStream outputFile = new FileOutputStream(filePath);
            convertToStream(outputFile);
            outputFile.close();
        }

        /**
        * Add a PDF file to the list of the input PDFs.
        *
        * @param filePath The file path to a local PDF file. The file must exist and not be empty.
        * @return The converter object.
        */
        public PdfToPdfClient addPdfFile(String filePath) {
            if (!(new File(filePath).length() > 0))
                throw new Error(createInvalidValueMessage(filePath, "addPdfFile", "pdf-to-pdf", "The file must exist and not be empty.", "add_pdf_file"), 470);
            
            files.put("f_" + Integer.toString(fileId), filePath);
            fileId++;
            return this;
        }

        /**
        * Add in-memory raw PDF data to the list of the input PDFs.<br>Typical usage is for adding PDF created by another Pdfcrowd converter.<br><br> Example in PHP:<br> <b>$clientPdf2Pdf</b>-&gt;addPdfRawData(<b>$clientHtml2Pdf</b>-&gt;convertUrl('http://www.example.com'));
        *
        * @param data The raw PDF data. The input data must be PDF content.
        * @return The converter object.
        */
        public PdfToPdfClient addPdfRawData(byte[] data) {
            if (!(data != null && data.length > 300 && (new String(data, 0, 4).equals("%PDF"))))
                throw new Error(createInvalidValueMessage("raw PDF data", "addPdfRawData", "pdf-to-pdf", "The input data must be PDF content.", "add_pdf_raw_data"), 470);
            
            rawData.put("f_" + Integer.toString(fileId), data);
            fileId++;
            return this;
        }

        /**
        * Password to open the encrypted PDF file.
        *
        * @param password The input PDF password.
        * @return The converter object.
        */
        public PdfToPdfClient setInputPdfPassword(String password) {
            fields.put("input_pdf_password", password);
            return this;
        }

        /**
        * Set the page range for <span class='field-value'>extract</span> or <span class='field-value'>delete</span> action.
        *
        * @param pages A comma separated list of page numbers or ranges.
        * @return The converter object.
        */
        public PdfToPdfClient setPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPageRange", "pdf-to-pdf", "A comma separated list of page numbers or ranges.", "set_page_range"), 470);
            
            fields.put("page_range", pages);
            return this;
        }

        /**
        * Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        *
        * @param watermark The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public PdfToPdfClient setPageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setPageWatermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            
            files.put("page_watermark", watermark);
            return this;
        }

        /**
        * Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public PdfToPdfClient setPageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageWatermarkUrl", "pdf-to-pdf", "The supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            
            fields.put("page_watermark_url", url);
            return this;
        }

        /**
        * Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        *
        * @param watermark The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public PdfToPdfClient setMultipageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setMultipageWatermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            
            files.put("multipage_watermark", watermark);
            return this;
        }

        /**
        * Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public PdfToPdfClient setMultipageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageWatermarkUrl", "pdf-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            
            fields.put("multipage_watermark_url", url);
            return this;
        }

        /**
        * Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        *
        * @param background The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public PdfToPdfClient setPageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setPageBackground", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            
            files.put("page_background", background);
            return this;
        }

        /**
        * Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public PdfToPdfClient setPageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageBackgroundUrl", "pdf-to-pdf", "The supported protocols are http:// and https://.", "set_page_background_url"), 470);
            
            fields.put("page_background_url", url);
            return this;
        }

        /**
        * Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        *
        * @param background The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public PdfToPdfClient setMultipageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setMultipageBackground", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            
            files.put("multipage_background", background);
            return this;
        }

        /**
        * Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public PdfToPdfClient setMultipageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageBackgroundUrl", "pdf-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            
            fields.put("multipage_background_url", url);
            return this;
        }

        /**
        * Create linearized PDF. This is also known as Fast Web View.
        *
        * @param value Set to <span class='field-value'>true</span> to create linearized PDF.
        * @return The converter object.
        */
        public PdfToPdfClient setLinearize(boolean value) {
            fields.put("linearize", value ? "true" : null);
            return this;
        }

        /**
        * Encrypt the PDF. This prevents search engines from indexing the contents.
        *
        * @param value Set to <span class='field-value'>true</span> to enable PDF encryption.
        * @return The converter object.
        */
        public PdfToPdfClient setEncrypt(boolean value) {
            fields.put("encrypt", value ? "true" : null);
            return this;
        }

        /**
        * Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        *
        * @param password The user password.
        * @return The converter object.
        */
        public PdfToPdfClient setUserPassword(String password) {
            fields.put("user_password", password);
            return this;
        }

        /**
        * Protect the PDF with an owner password.  Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        *
        * @param password The owner password.
        * @return The converter object.
        */
        public PdfToPdfClient setOwnerPassword(String password) {
            fields.put("owner_password", password);
            return this;
        }

        /**
        * Disallow printing of the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the no-print flag in the output PDF.
        * @return The converter object.
        */
        public PdfToPdfClient setNoPrint(boolean value) {
            fields.put("no_print", value ? "true" : null);
            return this;
        }

        /**
        * Disallow modification of the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the read-only only flag in the output PDF.
        * @return The converter object.
        */
        public PdfToPdfClient setNoModify(boolean value) {
            fields.put("no_modify", value ? "true" : null);
            return this;
        }

        /**
        * Disallow text and graphics extraction from the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the no-copy flag in the output PDF.
        * @return The converter object.
        */
        public PdfToPdfClient setNoCopy(boolean value) {
            fields.put("no_copy", value ? "true" : null);
            return this;
        }

        /**
        * Set the title of the PDF.
        *
        * @param title The title.
        * @return The converter object.
        */
        public PdfToPdfClient setTitle(String title) {
            fields.put("title", title);
            return this;
        }

        /**
        * Set the subject of the PDF.
        *
        * @param subject The subject.
        * @return The converter object.
        */
        public PdfToPdfClient setSubject(String subject) {
            fields.put("subject", subject);
            return this;
        }

        /**
        * Set the author of the PDF.
        *
        * @param author The author.
        * @return The converter object.
        */
        public PdfToPdfClient setAuthor(String author) {
            fields.put("author", author);
            return this;
        }

        /**
        * Associate keywords with the document.
        *
        * @param keywords The string with the keywords.
        * @return The converter object.
        */
        public PdfToPdfClient setKeywords(String keywords) {
            fields.put("keywords", keywords);
            return this;
        }

        /**
        * Use metadata (title, subject, author and keywords) from the n-th input PDF.
        *
        * @param index Set the index of the input PDF file from which to use the metadata. 0 means no metadata. Must be a positive integer number or 0.
        * @return The converter object.
        */
        public PdfToPdfClient setUseMetadataFrom(int index) {
            if (!(index >= 0))
                throw new Error(createInvalidValueMessage(index, "setUseMetadataFrom", "pdf-to-pdf", "Must be a positive integer number or 0.", "set_use_metadata_from"), 470);
            
            fields.put("use_metadata_from", Integer.toString(index));
            return this;
        }

        /**
        * Specify the page layout to be used when the document is opened.
        *
        * @param layout Allowed values are single-page, one-column, two-column-left, two-column-right.
        * @return The converter object.
        */
        public PdfToPdfClient setPageLayout(String layout) {
            if (!layout.matches("(?i)^(single-page|one-column|two-column-left|two-column-right)$"))
                throw new Error(createInvalidValueMessage(layout, "setPageLayout", "pdf-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            
            fields.put("page_layout", layout);
            return this;
        }

        /**
        * Specify how the document should be displayed when opened.
        *
        * @param mode Allowed values are full-screen, thumbnails, outlines.
        * @return The converter object.
        */
        public PdfToPdfClient setPageMode(String mode) {
            if (!mode.matches("(?i)^(full-screen|thumbnails|outlines)$"))
                throw new Error(createInvalidValueMessage(mode, "setPageMode", "pdf-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            
            fields.put("page_mode", mode);
            return this;
        }

        /**
        * Specify how the page should be displayed when opened.
        *
        * @param zoomType Allowed values are fit-width, fit-height, fit-page.
        * @return The converter object.
        */
        public PdfToPdfClient setInitialZoomType(String zoomType) {
            if (!zoomType.matches("(?i)^(fit-width|fit-height|fit-page)$"))
                throw new Error(createInvalidValueMessage(zoomType, "setInitialZoomType", "pdf-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            
            fields.put("initial_zoom_type", zoomType);
            return this;
        }

        /**
        * Display the specified page when the document is opened.
        *
        * @param page Must be a positive integer number.
        * @return The converter object.
        */
        public PdfToPdfClient setInitialPage(int page) {
            if (!(page > 0))
                throw new Error(createInvalidValueMessage(page, "setInitialPage", "pdf-to-pdf", "Must be a positive integer number.", "set_initial_page"), 470);
            
            fields.put("initial_page", Integer.toString(page));
            return this;
        }

        /**
        * Specify the initial page zoom in percents when the document is opened.
        *
        * @param zoom Must be a positive integer number.
        * @return The converter object.
        */
        public PdfToPdfClient setInitialZoom(int zoom) {
            if (!(zoom > 0))
                throw new Error(createInvalidValueMessage(zoom, "setInitialZoom", "pdf-to-pdf", "Must be a positive integer number.", "set_initial_zoom"), 470);
            
            fields.put("initial_zoom", Integer.toString(zoom));
            return this;
        }

        /**
        * Specify whether to hide the viewer application's tool bars when the document is active.
        *
        * @param value Set to <span class='field-value'>true</span> to hide tool bars.
        * @return The converter object.
        */
        public PdfToPdfClient setHideToolbar(boolean value) {
            fields.put("hide_toolbar", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to hide the viewer application's menu bar when the document is active.
        *
        * @param value Set to <span class='field-value'>true</span> to hide the menu bar.
        * @return The converter object.
        */
        public PdfToPdfClient setHideMenubar(boolean value) {
            fields.put("hide_menubar", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
        *
        * @param value Set to <span class='field-value'>true</span> to hide ui elements.
        * @return The converter object.
        */
        public PdfToPdfClient setHideWindowUi(boolean value) {
            fields.put("hide_window_ui", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to resize the document's window to fit the size of the first displayed page.
        *
        * @param value Set to <span class='field-value'>true</span> to resize the window.
        * @return The converter object.
        */
        public PdfToPdfClient setFitWindow(boolean value) {
            fields.put("fit_window", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to position the document's window in the center of the screen.
        *
        * @param value Set to <span class='field-value'>true</span> to center the window.
        * @return The converter object.
        */
        public PdfToPdfClient setCenterWindow(boolean value) {
            fields.put("center_window", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
        *
        * @param value Set to <span class='field-value'>true</span> to display the title.
        * @return The converter object.
        */
        public PdfToPdfClient setDisplayTitle(boolean value) {
            fields.put("display_title", value ? "true" : null);
            return this;
        }

        /**
        * Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
        *
        * @param value Set to <span class='field-value'>true</span> to set right-to-left reading order.
        * @return The converter object.
        */
        public PdfToPdfClient setRightToLeft(boolean value) {
            fields.put("right_to_left", value ? "true" : null);
            return this;
        }

        /**
        * Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the <a href='#get_debug_log_url'>getDebugLogUrl</a> method or available in <a href='/user/account/log/conversion/'>conversion statistics</a>.
        *
        * @param value Set to <span class='field-value'>true</span> to enable the debug logging.
        * @return The converter object.
        */
        public PdfToPdfClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
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
        * This method can only be called after a call to one of the convertXtoY methods.
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
        * Get the number of pages in the output document.
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
        * Get the version details.
        * @return API version, converter version, and client version.
        */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
        * Tag the conversion with a custom value. The tag is used in <a href='/user/account/log/conversion/'>conversion statistics</a>. A value longer than 32 characters is cut off.
        *
        * @param tag A string with the custom tag.
        * @return The converter object.
        */
        public PdfToPdfClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
        * Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        *
        * @param version The version identifier. Allowed values are latest, 20.10, 18.10.
        * @return The converter object.
        */
        public PdfToPdfClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(latest|20.10|18.10)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "pdf-to-pdf", "Allowed values are latest, 20.10, 18.10.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        *
        * @param value Set to <span class='field-value'>true</span> to use HTTP.
        * @return The converter object.
        */
        public PdfToPdfClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
        * Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        *
        * @param agent The user agent string.
        * @return The converter object.
        */
        public PdfToPdfClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        *
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        * @return The converter object.
        */
        public PdfToPdfClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
        * Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        *
        * @param count Number of retries.
        * @return The converter object.
        */
        public PdfToPdfClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
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
                throw new Error(createInvalidValueMessage(url, "convertUrl", "image-to-pdf", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
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
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "image-to-pdf", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
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
        * Convert a local file.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a local file and write the result to an output stream.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a local file and write the result to a local file.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @param filePath The output file path. The string must not be empty.
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
        * Convert the contents of an input stream.
        *
        * @param inStream The input stream with source data.<br>
        * @return Byte array containing the conversion output.
        */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert the contents of an input stream and write the result to an output stream.
        *
        * @param inStream The input stream with source data.<br>
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert the contents of an input stream and write the result to a local file.
        *
        * @param inStream The input stream with source data.<br>
        * @param filePath The output file path. The string must not be empty.
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
        * Resize the image.
        *
        * @param resize The resize percentage or new image dimensions.
        * @return The converter object.
        */
        public ImageToPdfClient setResize(String resize) {
            fields.put("resize", resize);
            return this;
        }

        /**
        * Rotate the image.
        *
        * @param rotate The rotation specified in degrees.
        * @return The converter object.
        */
        public ImageToPdfClient setRotate(String rotate) {
            fields.put("rotate", rotate);
            return this;
        }

        /**
        * Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
        *
        * @param x The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setCropAreaX(String x) {
            if (!x.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(x, "setCropAreaX", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_crop_area_x"), 470);
            
            fields.put("crop_area_x", x);
            return this;
        }

        /**
        * Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
        *
        * @param y The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setCropAreaY(String y) {
            if (!y.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(y, "setCropAreaY", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_crop_area_y"), 470);
            
            fields.put("crop_area_y", y);
            return this;
        }

        /**
        * Set the width of the content area. It should be at least 1 inch.
        *
        * @param width The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setCropAreaWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setCropAreaWidth", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_crop_area_width"), 470);
            
            fields.put("crop_area_width", width);
            return this;
        }

        /**
        * Set the height of the content area. It should be at least 1 inch.
        *
        * @param height The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setCropAreaHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setCropAreaHeight", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_crop_area_height"), 470);
            
            fields.put("crop_area_height", height);
            return this;
        }

        /**
        * Set the content area position and size. The content area enables to specify the part to be converted.
        *
        * @param x Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param y Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param width Set the width of the content area. It should be at least 1 inch. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param height Set the height of the content area. It should be at least 1 inch. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setCropArea(String x, String y, String width, String height) {
            this.setCropAreaX(x);
            this.setCropAreaY(y);
            this.setCropAreaWidth(width);
            this.setCropAreaHeight(height);
            return this;
        }

        /**
        * Remove borders of an image which does not change in color.
        *
        * @param value Set to <span class='field-value'>true</span> to remove borders.
        * @return The converter object.
        */
        public ImageToPdfClient setRemoveBorders(boolean value) {
            fields.put("remove_borders", value ? "true" : null);
            return this;
        }

        /**
        * Set the output page size.
        *
        * @param size Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
        * @return The converter object.
        */
        public ImageToPdfClient setPageSize(String size) {
            if (!size.matches("(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$"))
                throw new Error(createInvalidValueMessage(size, "setPageSize", "image-to-pdf", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            
            fields.put("page_size", size);
            return this;
        }

        /**
        * Set the output page width.
        *
        * @param width The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setPageWidth(String width) {
            if (!width.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(width, "setPageWidth", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_page_width"), 470);
            
            fields.put("page_width", width);
            return this;
        }

        /**
        * Set the output page height.
        *
        * @param height The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setPageHeight(String height) {
            if (!height.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(height, "setPageHeight", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_page_height"), 470);
            
            fields.put("page_height", height);
            return this;
        }

        /**
        * Set the output page dimensions. If no page size is specified, margins are applied as a border around the image.
        *
        * @param width Set the output page width. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param height Set the output page height. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setPageDimensions(String width, String height) {
            this.setPageWidth(width);
            this.setPageHeight(height);
            return this;
        }

        /**
        * Set the output page orientation.
        *
        * @param orientation Allowed values are landscape, portrait.
        * @return The converter object.
        */
        public ImageToPdfClient setOrientation(String orientation) {
            if (!orientation.matches("(?i)^(landscape|portrait)$"))
                throw new Error(createInvalidValueMessage(orientation, "setOrientation", "image-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            
            fields.put("orientation", orientation);
            return this;
        }

        /**
        * Set the image position on the page.
        *
        * @param position Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.
        * @return The converter object.
        */
        public ImageToPdfClient setPosition(String position) {
            if (!position.matches("(?i)^(center|top|bottom|left|right|top-left|top-right|bottom-left|bottom-right)$"))
                throw new Error(createInvalidValueMessage(position, "setPosition", "image-to-pdf", "Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.", "set_position"), 470);
            
            fields.put("position", position);
            return this;
        }

        /**
        * Set the mode to print the image on the content area of the page.
        *
        * @param mode Allowed values are default, fit, stretch.
        * @return The converter object.
        */
        public ImageToPdfClient setPrintPageMode(String mode) {
            if (!mode.matches("(?i)^(default|fit|stretch)$"))
                throw new Error(createInvalidValueMessage(mode, "setPrintPageMode", "image-to-pdf", "Allowed values are default, fit, stretch.", "set_print_page_mode"), 470);
            
            fields.put("print_page_mode", mode);
            return this;
        }

        /**
        * Set the output page top margin.
        *
        * @param top The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setMarginTop(String top) {
            if (!top.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(top, "setMarginTop", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_top"), 470);
            
            fields.put("margin_top", top);
            return this;
        }

        /**
        * Set the output page right margin.
        *
        * @param right The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setMarginRight(String right) {
            if (!right.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(right, "setMarginRight", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_right"), 470);
            
            fields.put("margin_right", right);
            return this;
        }

        /**
        * Set the output page bottom margin.
        *
        * @param bottom The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setMarginBottom(String bottom) {
            if (!bottom.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(bottom, "setMarginBottom", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_bottom"), 470);
            
            fields.put("margin_bottom", bottom);
            return this;
        }

        /**
        * Set the output page left margin.
        *
        * @param left The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setMarginLeft(String left) {
            if (!left.matches("(?i)^0$|^[0-9]*\\.?[0-9]+(pt|px|mm|cm|in)$"))
                throw new Error(createInvalidValueMessage(left, "setMarginLeft", "image-to-pdf", "The value must be specified in inches \"in\", millimeters \"mm\", centimeters \"cm\", pixels \"px\", or points \"pt\".", "set_margin_left"), 470);
            
            fields.put("margin_left", left);
            return this;
        }

        /**
        * Set the output page margins.
        *
        * @param top Set the output page top margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param right Set the output page right margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param bottom Set the output page bottom margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @param left Set the output page left margin. The value must be specified in inches "in", millimeters "mm", centimeters "cm", pixels "px", or points "pt".
        * @return The converter object.
        */
        public ImageToPdfClient setPageMargins(String top, String right, String bottom, String left) {
            this.setMarginTop(top);
            this.setMarginRight(right);
            this.setMarginBottom(bottom);
            this.setMarginLeft(left);
            return this;
        }

        /**
        * The page background color in RGB or RGBA hexadecimal format. The color fills the entire page regardless of the margins. If not page size is specified and the image format supports background (e.g. PDF, PNG), the background color is applied too.
        *
        * @param color The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        * @return The converter object.
        */
        public ImageToPdfClient setPageBackgroundColor(String color) {
            if (!color.matches("^[0-9a-fA-F]{6,8}$"))
                throw new Error(createInvalidValueMessage(color, "setPageBackgroundColor", "image-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            
            fields.put("page_background_color", color);
            return this;
        }

        /**
        * Set the DPI resolution of the input image. The DPI affects margin options specified in points too (e.g. 1 point is equal to 1 pixel in 96 DPI).
        *
        * @param dpi The DPI value.
        * @return The converter object.
        */
        public ImageToPdfClient setDpi(int dpi) {
            fields.put("dpi", Integer.toString(dpi));
            return this;
        }

        /**
        * Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        *
        * @param watermark The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public ImageToPdfClient setPageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setPageWatermark", "image-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            
            files.put("page_watermark", watermark);
            return this;
        }

        /**
        * Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public ImageToPdfClient setPageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageWatermarkUrl", "image-to-pdf", "The supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            
            fields.put("page_watermark_url", url);
            return this;
        }

        /**
        * Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        *
        * @param watermark The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public ImageToPdfClient setMultipageWatermark(String watermark) {
            if (!(new File(watermark).length() > 0))
                throw new Error(createInvalidValueMessage(watermark, "setMultipageWatermark", "image-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            
            files.put("multipage_watermark", watermark);
            return this;
        }

        /**
        * Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public ImageToPdfClient setMultipageWatermarkUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageWatermarkUrl", "image-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            
            fields.put("multipage_watermark_url", url);
            return this;
        }

        /**
        * Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        *
        * @param background The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public ImageToPdfClient setPageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setPageBackground", "image-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            
            files.put("page_background", background);
            return this;
        }

        /**
        * Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public ImageToPdfClient setPageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setPageBackgroundUrl", "image-to-pdf", "The supported protocols are http:// and https://.", "set_page_background_url"), 470);
            
            fields.put("page_background_url", url);
            return this;
        }

        /**
        * Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        *
        * @param background The file path to a local file. The file must exist and not be empty.
        * @return The converter object.
        */
        public ImageToPdfClient setMultipageBackground(String background) {
            if (!(new File(background).length() > 0))
                throw new Error(createInvalidValueMessage(background, "setMultipageBackground", "image-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            
            files.put("multipage_background", background);
            return this;
        }

        /**
        * Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        *
        * @param url The supported protocols are http:// and https://.
        * @return The converter object.
        */
        public ImageToPdfClient setMultipageBackgroundUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "setMultipageBackgroundUrl", "image-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            
            fields.put("multipage_background_url", url);
            return this;
        }

        /**
        * Create linearized PDF. This is also known as Fast Web View.
        *
        * @param value Set to <span class='field-value'>true</span> to create linearized PDF.
        * @return The converter object.
        */
        public ImageToPdfClient setLinearize(boolean value) {
            fields.put("linearize", value ? "true" : null);
            return this;
        }

        /**
        * Encrypt the PDF. This prevents search engines from indexing the contents.
        *
        * @param value Set to <span class='field-value'>true</span> to enable PDF encryption.
        * @return The converter object.
        */
        public ImageToPdfClient setEncrypt(boolean value) {
            fields.put("encrypt", value ? "true" : null);
            return this;
        }

        /**
        * Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        *
        * @param password The user password.
        * @return The converter object.
        */
        public ImageToPdfClient setUserPassword(String password) {
            fields.put("user_password", password);
            return this;
        }

        /**
        * Protect the PDF with an owner password.  Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        *
        * @param password The owner password.
        * @return The converter object.
        */
        public ImageToPdfClient setOwnerPassword(String password) {
            fields.put("owner_password", password);
            return this;
        }

        /**
        * Disallow printing of the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the no-print flag in the output PDF.
        * @return The converter object.
        */
        public ImageToPdfClient setNoPrint(boolean value) {
            fields.put("no_print", value ? "true" : null);
            return this;
        }

        /**
        * Disallow modification of the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the read-only only flag in the output PDF.
        * @return The converter object.
        */
        public ImageToPdfClient setNoModify(boolean value) {
            fields.put("no_modify", value ? "true" : null);
            return this;
        }

        /**
        * Disallow text and graphics extraction from the output PDF.
        *
        * @param value Set to <span class='field-value'>true</span> to set the no-copy flag in the output PDF.
        * @return The converter object.
        */
        public ImageToPdfClient setNoCopy(boolean value) {
            fields.put("no_copy", value ? "true" : null);
            return this;
        }

        /**
        * Set the title of the PDF.
        *
        * @param title The title.
        * @return The converter object.
        */
        public ImageToPdfClient setTitle(String title) {
            fields.put("title", title);
            return this;
        }

        /**
        * Set the subject of the PDF.
        *
        * @param subject The subject.
        * @return The converter object.
        */
        public ImageToPdfClient setSubject(String subject) {
            fields.put("subject", subject);
            return this;
        }

        /**
        * Set the author of the PDF.
        *
        * @param author The author.
        * @return The converter object.
        */
        public ImageToPdfClient setAuthor(String author) {
            fields.put("author", author);
            return this;
        }

        /**
        * Associate keywords with the document.
        *
        * @param keywords The string with the keywords.
        * @return The converter object.
        */
        public ImageToPdfClient setKeywords(String keywords) {
            fields.put("keywords", keywords);
            return this;
        }

        /**
        * Specify the page layout to be used when the document is opened.
        *
        * @param layout Allowed values are single-page, one-column, two-column-left, two-column-right.
        * @return The converter object.
        */
        public ImageToPdfClient setPageLayout(String layout) {
            if (!layout.matches("(?i)^(single-page|one-column|two-column-left|two-column-right)$"))
                throw new Error(createInvalidValueMessage(layout, "setPageLayout", "image-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            
            fields.put("page_layout", layout);
            return this;
        }

        /**
        * Specify how the document should be displayed when opened.
        *
        * @param mode Allowed values are full-screen, thumbnails, outlines.
        * @return The converter object.
        */
        public ImageToPdfClient setPageMode(String mode) {
            if (!mode.matches("(?i)^(full-screen|thumbnails|outlines)$"))
                throw new Error(createInvalidValueMessage(mode, "setPageMode", "image-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            
            fields.put("page_mode", mode);
            return this;
        }

        /**
        * Specify how the page should be displayed when opened.
        *
        * @param zoomType Allowed values are fit-width, fit-height, fit-page.
        * @return The converter object.
        */
        public ImageToPdfClient setInitialZoomType(String zoomType) {
            if (!zoomType.matches("(?i)^(fit-width|fit-height|fit-page)$"))
                throw new Error(createInvalidValueMessage(zoomType, "setInitialZoomType", "image-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            
            fields.put("initial_zoom_type", zoomType);
            return this;
        }

        /**
        * Display the specified page when the document is opened.
        *
        * @param page Must be a positive integer number.
        * @return The converter object.
        */
        public ImageToPdfClient setInitialPage(int page) {
            if (!(page > 0))
                throw new Error(createInvalidValueMessage(page, "setInitialPage", "image-to-pdf", "Must be a positive integer number.", "set_initial_page"), 470);
            
            fields.put("initial_page", Integer.toString(page));
            return this;
        }

        /**
        * Specify the initial page zoom in percents when the document is opened.
        *
        * @param zoom Must be a positive integer number.
        * @return The converter object.
        */
        public ImageToPdfClient setInitialZoom(int zoom) {
            if (!(zoom > 0))
                throw new Error(createInvalidValueMessage(zoom, "setInitialZoom", "image-to-pdf", "Must be a positive integer number.", "set_initial_zoom"), 470);
            
            fields.put("initial_zoom", Integer.toString(zoom));
            return this;
        }

        /**
        * Specify whether to hide the viewer application's tool bars when the document is active.
        *
        * @param value Set to <span class='field-value'>true</span> to hide tool bars.
        * @return The converter object.
        */
        public ImageToPdfClient setHideToolbar(boolean value) {
            fields.put("hide_toolbar", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to hide the viewer application's menu bar when the document is active.
        *
        * @param value Set to <span class='field-value'>true</span> to hide the menu bar.
        * @return The converter object.
        */
        public ImageToPdfClient setHideMenubar(boolean value) {
            fields.put("hide_menubar", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
        *
        * @param value Set to <span class='field-value'>true</span> to hide ui elements.
        * @return The converter object.
        */
        public ImageToPdfClient setHideWindowUi(boolean value) {
            fields.put("hide_window_ui", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to resize the document's window to fit the size of the first displayed page.
        *
        * @param value Set to <span class='field-value'>true</span> to resize the window.
        * @return The converter object.
        */
        public ImageToPdfClient setFitWindow(boolean value) {
            fields.put("fit_window", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether to position the document's window in the center of the screen.
        *
        * @param value Set to <span class='field-value'>true</span> to center the window.
        * @return The converter object.
        */
        public ImageToPdfClient setCenterWindow(boolean value) {
            fields.put("center_window", value ? "true" : null);
            return this;
        }

        /**
        * Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
        *
        * @param value Set to <span class='field-value'>true</span> to display the title.
        * @return The converter object.
        */
        public ImageToPdfClient setDisplayTitle(boolean value) {
            fields.put("display_title", value ? "true" : null);
            return this;
        }

        /**
        * Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the <a href='#get_debug_log_url'>getDebugLogUrl</a> method or available in <a href='/user/account/log/conversion/'>conversion statistics</a>.
        *
        * @param value Set to <span class='field-value'>true</span> to enable the debug logging.
        * @return The converter object.
        */
        public ImageToPdfClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
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
        * This method can only be called after a call to one of the convertXtoY methods.
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
        * Get the version details.
        * @return API version, converter version, and client version.
        */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
        * Tag the conversion with a custom value. The tag is used in <a href='/user/account/log/conversion/'>conversion statistics</a>. A value longer than 32 characters is cut off.
        *
        * @param tag A string with the custom tag.
        * @return The converter object.
        */
        public ImageToPdfClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public ImageToPdfClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public ImageToPdfClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
        * Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        *
        * @param version The version identifier. Allowed values are latest, 20.10, 18.10.
        * @return The converter object.
        */
        public ImageToPdfClient setConverterVersion(String version) {
            if (!version.matches("(?i)^(latest|20.10|18.10)$"))
                throw new Error(createInvalidValueMessage(version, "setConverterVersion", "image-to-pdf", "Allowed values are latest, 20.10, 18.10.", "set_converter_version"), 470);
            
            helper.setConverterVersion(version);
            return this;
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        *
        * @param value Set to <span class='field-value'>true</span> to use HTTP.
        * @return The converter object.
        */
        public ImageToPdfClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
        * Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        *
        * @param agent The user agent string.
        * @return The converter object.
        */
        public ImageToPdfClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        *
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        * @return The converter object.
        */
        public ImageToPdfClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
        * Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        *
        * @param count Number of retries.
        * @return The converter object.
        */
        public ImageToPdfClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

    /**
    * Conversion from PDF to HTML.
    */
    public static final class PdfToHtmlClient {
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
        public PdfToHtmlClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "pdf");
            fields.put("output_format", "html");
        }

        /**
        * Convert a PDF.
        *
        * @param url The address of the PDF to convert. The supported protocols are http:// and https://.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "pdf-to-html", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a PDF and write the result to an output stream.
        *
        * @param url The address of the PDF to convert. The supported protocols are http:// and https://.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "pdf-to-html", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a PDF and write the result to a local file.
        *
        * @param url The address of the PDF to convert. The supported protocols are http:// and https://.
        * @param filePath The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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
        * Convert a local file.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "pdf-to-html", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a local file and write the result to an output stream.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "pdf-to-html", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a local file and write the result to a local file.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @param filePath The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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
        * @param filePath The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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
        * Convert the contents of an input stream.
        *
        * @param inStream The input stream with source data.<br>
        * @return Byte array containing the conversion output.
        */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert the contents of an input stream and write the result to an output stream.
        *
        * @param inStream The input stream with source data.<br>
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert the contents of an input stream and write the result to a local file.
        *
        * @param inStream The input stream with source data.<br>
        * @param filePath The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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
        * Password to open the encrypted PDF file.
        *
        * @param password The input PDF password.
        * @return The converter object.
        */
        public PdfToHtmlClient setPdfPassword(String password) {
            fields.put("pdf_password", password);
            return this;
        }

        /**
        * Set the scaling factor (zoom) for the main page area.
        *
        * @param factor The percentage value. Must be a positive integer number.
        * @return The converter object.
        */
        public PdfToHtmlClient setScaleFactor(int factor) {
            if (!(factor > 0))
                throw new Error(createInvalidValueMessage(factor, "setScaleFactor", "pdf-to-html", "Must be a positive integer number.", "set_scale_factor"), 470);
            
            fields.put("scale_factor", Integer.toString(factor));
            return this;
        }

        /**
        * Set the page range to print.
        *
        * @param pages A comma separated list of page numbers or ranges.
        * @return The converter object.
        */
        public PdfToHtmlClient setPrintPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPrintPageRange", "pdf-to-html", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            
            fields.put("print_page_range", pages);
            return this;
        }

        /**
        * Set the output graphics DPI.
        *
        * @param dpi The DPI value.
        * @return The converter object.
        */
        public PdfToHtmlClient setDpi(int dpi) {
            fields.put("dpi", Integer.toString(dpi));
            return this;
        }

        /**
        * Specifies where the images are stored.
        *
        * @param mode The image storage mode. Allowed values are embed, separate, none.
        * @return The converter object.
        */
        public PdfToHtmlClient setImageMode(String mode) {
            if (!mode.matches("(?i)^(embed|separate|none)$"))
                throw new Error(createInvalidValueMessage(mode, "setImageMode", "pdf-to-html", "Allowed values are embed, separate, none.", "set_image_mode"), 470);
            
            fields.put("image_mode", mode);
            return this;
        }

        /**
        * Specifies the format for the output images.
        *
        * @param imageFormat The image format. Allowed values are png, jpg, svg.
        * @return The converter object.
        */
        public PdfToHtmlClient setImageFormat(String imageFormat) {
            if (!imageFormat.matches("(?i)^(png|jpg|svg)$"))
                throw new Error(createInvalidValueMessage(imageFormat, "setImageFormat", "pdf-to-html", "Allowed values are png, jpg, svg.", "set_image_format"), 470);
            
            fields.put("image_format", imageFormat);
            return this;
        }

        /**
        * Specifies where the style sheets are stored.
        *
        * @param mode The style sheet storage mode. Allowed values are embed, separate.
        * @return The converter object.
        */
        public PdfToHtmlClient setCssMode(String mode) {
            if (!mode.matches("(?i)^(embed|separate)$"))
                throw new Error(createInvalidValueMessage(mode, "setCssMode", "pdf-to-html", "Allowed values are embed, separate.", "set_css_mode"), 470);
            
            fields.put("css_mode", mode);
            return this;
        }

        /**
        * Specifies where the fonts are stored.
        *
        * @param mode The font storage mode. Allowed values are embed, separate.
        * @return The converter object.
        */
        public PdfToHtmlClient setFontMode(String mode) {
            if (!mode.matches("(?i)^(embed|separate)$"))
                throw new Error(createInvalidValueMessage(mode, "setFontMode", "pdf-to-html", "Allowed values are embed, separate.", "set_font_mode"), 470);
            
            fields.put("font_mode", mode);
            return this;
        }

        /**
        * Converts ligatures — two or more letters combined into a single glyph—back into their individual ASCII characters.
        *
        * @param value Set to <span class='field-value'>true</span> to split ligatures.
        * @return The converter object.
        */
        public PdfToHtmlClient setSplitLigatures(boolean value) {
            fields.put("split_ligatures", value ? "true" : null);
            return this;
        }

        /**
        * A helper method to determine if the output file is a zip archive. The output of the conversion may be either an HTML file or a zip file containing the HTML and its external assets.
        * @return <span class='field-value'>True</span> if the conversion output is a zip file, otherwise <span class='field-value'>False</span>.
        */
        public boolean isZippedOutput() {
            return "separate".equals(fields.get("image_mode")) || "separate".equals(fields.get("css_mode")) || "separate".equals(fields.get("font_mode")) || "true".equals(fields.get("force_zip"));
        }

        /**
        * Enforces the zip output format.
        *
        * @param value Set to <span class='field-value'>true</span> to get the output as a zip archive.
        * @return The converter object.
        */
        public PdfToHtmlClient setForceZip(boolean value) {
            fields.put("force_zip", value ? "true" : null);
            return this;
        }

        /**
        * Set the HTML title. The title from the input PDF is used by default.
        *
        * @param title The HTML title.
        * @return The converter object.
        */
        public PdfToHtmlClient setTitle(String title) {
            fields.put("title", title);
            return this;
        }

        /**
        * Set the HTML subject. The subject from the input PDF is used by default.
        *
        * @param subject The HTML subject.
        * @return The converter object.
        */
        public PdfToHtmlClient setSubject(String subject) {
            fields.put("subject", subject);
            return this;
        }

        /**
        * Set the HTML author. The author from the input PDF is used by default.
        *
        * @param author The HTML author.
        * @return The converter object.
        */
        public PdfToHtmlClient setAuthor(String author) {
            fields.put("author", author);
            return this;
        }

        /**
        * Associate keywords with the HTML document. Keywords from the input PDF are used by default.
        *
        * @param keywords The string containing the keywords.
        * @return The converter object.
        */
        public PdfToHtmlClient setKeywords(String keywords) {
            fields.put("keywords", keywords);
            return this;
        }

        /**
        * Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the <a href='#get_debug_log_url'>getDebugLogUrl</a> method or available in <a href='/user/account/log/conversion/'>conversion statistics</a>.
        *
        * @param value Set to <span class='field-value'>true</span> to enable the debug logging.
        * @return The converter object.
        */
        public PdfToHtmlClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
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
        * This method can only be called after a call to one of the convertXtoY methods.
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
        * Get the number of pages in the output document.
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
        * Get the version details.
        * @return API version, converter version, and client version.
        */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
        * Tag the conversion with a custom value. The tag is used in <a href='/user/account/log/conversion/'>conversion statistics</a>. A value longer than 32 characters is cut off.
        *
        * @param tag A string with the custom tag.
        * @return The converter object.
        */
        public PdfToHtmlClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public PdfToHtmlClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "pdf-to-html", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public PdfToHtmlClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "pdf-to-html", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        *
        * @param value Set to <span class='field-value'>true</span> to use HTTP.
        * @return The converter object.
        */
        public PdfToHtmlClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
        * Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        *
        * @param agent The user agent string.
        * @return The converter object.
        */
        public PdfToHtmlClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        *
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        * @return The converter object.
        */
        public PdfToHtmlClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
        * Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        *
        * @param count Number of retries.
        * @return The converter object.
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
    */
    public static final class PdfToTextClient {
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
        public PdfToTextClient(String userName, String apiKey) {
            this.helper = new ConnectionHelper(userName, apiKey);
            fields.put("input_format", "pdf");
            fields.put("output_format", "txt");
        }

        /**
        * Convert a PDF.
        *
        * @param url The address of the PDF to convert. The supported protocols are http:// and https://.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertUrl(String url) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrl", "pdf-to-text", "The supported protocols are http:// and https://.", "convert_url"), 470);
            
            fields.put("url", url);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a PDF and write the result to an output stream.
        *
        * @param url The address of the PDF to convert. The supported protocols are http:// and https://.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertUrlToStream(String url, OutputStream outStream) {
            if (!url.matches("(?i)^https?://.*$"))
                throw new Error(createInvalidValueMessage(url, "convertUrlToStream::url", "pdf-to-text", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            
            fields.put("url", url);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a PDF and write the result to a local file.
        *
        * @param url The address of the PDF to convert. The supported protocols are http:// and https://.
        * @param filePath The output file path. The string must not be empty.
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
        * Convert a local file.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @return Byte array containing the conversion output.
        */
        public byte[] convertFile(String file) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFile", "pdf-to-text", "The file must exist and not be empty.", "convert_file"), 470);
            
            files.put("file", file);
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert a local file and write the result to an output stream.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertFileToStream(String file, OutputStream outStream) {
            if (!(new File(file).length() > 0))
                throw new Error(createInvalidValueMessage(file, "convertFileToStream::file", "pdf-to-text", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            
            files.put("file", file);
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert a local file and write the result to a local file.
        *
        * @param file The path to a local file to convert.<br>  The file must exist and not be empty.
        * @param filePath The output file path. The string must not be empty.
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
        * Convert the contents of an input stream.
        *
        * @param inStream The input stream with source data.<br>
        * @return Byte array containing the conversion output.
        */
        public byte[] convertStream(InputStream inStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            return helper.post(fields, files, rawData, null);
        }

        /**
        * Convert the contents of an input stream and write the result to an output stream.
        *
        * @param inStream The input stream with source data.<br>
        * @param outStream The output stream that will contain the conversion output.
        */
        public void convertStreamToStream(InputStream inStream, OutputStream outStream) throws IOException {
            rawData.put("stream", helper.getBytes(inStream));
            helper.post(fields, files, rawData, outStream);
        }

        /**
        * Convert the contents of an input stream and write the result to a local file.
        *
        * @param inStream The input stream with source data.<br>
        * @param filePath The output file path. The string must not be empty.
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
        * The password to open the encrypted PDF file.
        *
        * @param password The input PDF password.
        * @return The converter object.
        */
        public PdfToTextClient setPdfPassword(String password) {
            fields.put("pdf_password", password);
            return this;
        }

        /**
        * Set the page range to print.
        *
        * @param pages A comma separated list of page numbers or ranges.
        * @return The converter object.
        */
        public PdfToTextClient setPrintPageRange(String pages) {
            if (!pages.matches("^(?:\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*,\\s*)*\\s*(?:\\d+|(?:\\d*\\s*\\-\\s*\\d+)|(?:\\d+\\s*\\-\\s*\\d*))\\s*$"))
                throw new Error(createInvalidValueMessage(pages, "setPrintPageRange", "pdf-to-text", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            
            fields.put("print_page_range", pages);
            return this;
        }

        /**
        * Ignore the original PDF layout.
        *
        * @param value Set to <span class='field-value'>true</span> to ignore the layout.
        * @return The converter object.
        */
        public PdfToTextClient setNoLayout(boolean value) {
            fields.put("no_layout", value ? "true" : null);
            return this;
        }

        /**
        * The end-of-line convention for the text output.
        *
        * @param eol Allowed values are unix, dos, mac.
        * @return The converter object.
        */
        public PdfToTextClient setEol(String eol) {
            if (!eol.matches("(?i)^(unix|dos|mac)$"))
                throw new Error(createInvalidValueMessage(eol, "setEol", "pdf-to-text", "Allowed values are unix, dos, mac.", "set_eol"), 470);
            
            fields.put("eol", eol);
            return this;
        }

        /**
        * Specify the page break mode for the text output.
        *
        * @param mode Allowed values are none, default, custom.
        * @return The converter object.
        */
        public PdfToTextClient setPageBreakMode(String mode) {
            if (!mode.matches("(?i)^(none|default|custom)$"))
                throw new Error(createInvalidValueMessage(mode, "setPageBreakMode", "pdf-to-text", "Allowed values are none, default, custom.", "set_page_break_mode"), 470);
            
            fields.put("page_break_mode", mode);
            return this;
        }

        /**
        * Specify the custom page break.
        *
        * @param pageBreak String to insert between the pages.
        * @return The converter object.
        */
        public PdfToTextClient setCustomPageBreak(String pageBreak) {
            fields.put("custom_page_break", pageBreak);
            return this;
        }

        /**
        * Specify the paragraph detection mode.
        *
        * @param mode Allowed values are none, bounding-box, characters.
        * @return The converter object.
        */
        public PdfToTextClient setParagraphMode(String mode) {
            if (!mode.matches("(?i)^(none|bounding-box|characters)$"))
                throw new Error(createInvalidValueMessage(mode, "setParagraphMode", "pdf-to-text", "Allowed values are none, bounding-box, characters.", "set_paragraph_mode"), 470);
            
            fields.put("paragraph_mode", mode);
            return this;
        }

        /**
        * Set the maximum line spacing when the paragraph detection mode is enabled.
        *
        * @param threshold The value must be a positive integer percentage.
        * @return The converter object.
        */
        public PdfToTextClient setLineSpacingThreshold(String threshold) {
            if (!threshold.matches("(?i)^0$|^[0-9]+%$"))
                throw new Error(createInvalidValueMessage(threshold, "setLineSpacingThreshold", "pdf-to-text", "The value must be a positive integer percentage.", "set_line_spacing_threshold"), 470);
            
            fields.put("line_spacing_threshold", threshold);
            return this;
        }

        /**
        * Remove the hyphen character from the end of lines.
        *
        * @param value Set to <span class='field-value'>true</span> to remove hyphens.
        * @return The converter object.
        */
        public PdfToTextClient setRemoveHyphenation(boolean value) {
            fields.put("remove_hyphenation", value ? "true" : null);
            return this;
        }

        /**
        * Remove empty lines from the text output.
        *
        * @param value Set to <span class='field-value'>true</span> to remove empty lines.
        * @return The converter object.
        */
        public PdfToTextClient setRemoveEmptyLines(boolean value) {
            fields.put("remove_empty_lines", value ? "true" : null);
            return this;
        }

        /**
        * Set the top left X coordinate of the crop area in points.
        *
        * @param x Must be a positive integer number or 0.
        * @return The converter object.
        */
        public PdfToTextClient setCropAreaX(int x) {
            if (!(x >= 0))
                throw new Error(createInvalidValueMessage(x, "setCropAreaX", "pdf-to-text", "Must be a positive integer number or 0.", "set_crop_area_x"), 470);
            
            fields.put("crop_area_x", Integer.toString(x));
            return this;
        }

        /**
        * Set the top left Y coordinate of the crop area in points.
        *
        * @param y Must be a positive integer number or 0.
        * @return The converter object.
        */
        public PdfToTextClient setCropAreaY(int y) {
            if (!(y >= 0))
                throw new Error(createInvalidValueMessage(y, "setCropAreaY", "pdf-to-text", "Must be a positive integer number or 0.", "set_crop_area_y"), 470);
            
            fields.put("crop_area_y", Integer.toString(y));
            return this;
        }

        /**
        * Set the width of the crop area in points.
        *
        * @param width Must be a positive integer number or 0.
        * @return The converter object.
        */
        public PdfToTextClient setCropAreaWidth(int width) {
            if (!(width >= 0))
                throw new Error(createInvalidValueMessage(width, "setCropAreaWidth", "pdf-to-text", "Must be a positive integer number or 0.", "set_crop_area_width"), 470);
            
            fields.put("crop_area_width", Integer.toString(width));
            return this;
        }

        /**
        * Set the height of the crop area in points.
        *
        * @param height Must be a positive integer number or 0.
        * @return The converter object.
        */
        public PdfToTextClient setCropAreaHeight(int height) {
            if (!(height >= 0))
                throw new Error(createInvalidValueMessage(height, "setCropAreaHeight", "pdf-to-text", "Must be a positive integer number or 0.", "set_crop_area_height"), 470);
            
            fields.put("crop_area_height", Integer.toString(height));
            return this;
        }

        /**
        * Set the crop area. It allows to extract just a part of a PDF page.
        *
        * @param x Set the top left X coordinate of the crop area in points. Must be a positive integer number or 0.
        * @param y Set the top left Y coordinate of the crop area in points. Must be a positive integer number or 0.
        * @param width Set the width of the crop area in points. Must be a positive integer number or 0.
        * @param height Set the height of the crop area in points. Must be a positive integer number or 0.
        * @return The converter object.
        */
        public PdfToTextClient setCropArea(int x, int y, int width, int height) {
            this.setCropAreaX(x);
            this.setCropAreaY(y);
            this.setCropAreaWidth(width);
            this.setCropAreaHeight(height);
            return this;
        }

        /**
        * Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the <a href='#get_debug_log_url'>getDebugLogUrl</a> method or available in <a href='/user/account/log/conversion/'>conversion statistics</a>.
        *
        * @param value Set to <span class='field-value'>true</span> to enable the debug logging.
        * @return The converter object.
        */
        public PdfToTextClient setDebugLog(boolean value) {
            fields.put("debug_log", value ? "true" : null);
            return this;
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
        * This method can only be called after a call to one of the convertXtoY methods.
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
        * Get the number of pages in the output document.
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
        * Get the version details.
        * @return API version, converter version, and client version.
        */
        public String getVersion() {
            return String.format("client %s, API v2, converter %s", CLIENT_VERSION, helper.getConverterVersion());
        }

        /**
        * Tag the conversion with a custom value. The tag is used in <a href='/user/account/log/conversion/'>conversion statistics</a>. A value longer than 32 characters is cut off.
        *
        * @param tag A string with the custom tag.
        * @return The converter object.
        */
        public PdfToTextClient setTag(String tag) {
            fields.put("tag", tag);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public PdfToTextClient setHttpProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpProxy", "pdf-to-text", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            
            fields.put("http_proxy", proxy);
            return this;
        }

        /**
        * A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        *
        * @param proxy The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        * @return The converter object.
        */
        public PdfToTextClient setHttpsProxy(String proxy) {
            if (!proxy.matches("(?i)^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{1,}:\\d+$"))
                throw new Error(createInvalidValueMessage(proxy, "setHttpsProxy", "pdf-to-text", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            
            fields.put("https_proxy", proxy);
            return this;
        }

        /**
        * Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        * Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        *
        * @param value Set to <span class='field-value'>true</span> to use HTTP.
        * @return The converter object.
        */
        public PdfToTextClient setUseHttp(boolean value) {
            this.helper.setUseHttp(value);
            return this;
        }

        /**
        * Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        *
        * @param agent The user agent string.
        * @return The converter object.
        */
        public PdfToTextClient setUserAgent(String agent) {
            helper.setUserAgent(agent);
            return this;
        }

        /**
        * Specifies an HTTP proxy that the API client library will use to connect to the internet.
        *
        * @param host The proxy hostname.
        * @param port The proxy port.
        * @param userName The username.
        * @param password The password.
        * @return The converter object.
        */
        public PdfToTextClient setProxy(String host, int port, String userName, String password) {
            helper.setProxy(host, port, userName, password);
            return this;
        }

        /**
        * Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        *
        * @param count Number of retries.
        * @return The converter object.
        */
        public PdfToTextClient setRetryCount(int count) {
            this.helper.setRetryCount(count);
            return this;
        }

    }

}
