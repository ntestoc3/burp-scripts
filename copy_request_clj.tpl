[% if common-code %]
(require '[clj-http.client :as client])
(require '[clj-http.cookies :as cookies])
(import org.apache.http.impl.cookie.BasicClientCookie2)

(defn new-cookie
  [name value domain]
  (let [c (cookies/to-basic-client-cookie
           [name
            {:discard false
             :domain domain
             :path "/"
             :secure false,
             :expires nil
             :value value}])]
    (.setAttribute c BasicClientCookie2/DOMAIN_ATTR "true")
    c))

(def my-cs (clj-http.cookies/cookie-store))

(def my-proxy {:proxy-host "localhost"
               :proxy-port 8080})
(def use-proxy false)

(def common-opts (merge {:insecure? true
                         :cookie-policy :standard
                         :throw-exceptions false}
                        (when use-proxy
                          my-proxy)))
[% endif %]
[% safe %]
[% for info in items %]
[% for c in info.cookies %]
(cookies/add-cookie my-cs (new-cookie "[{c.k}]" "[{c.v}]" "[{c.domain}]"))[% endfor %]
(def burp[{info.id}]-url "[{info.url}]")
(def burp[{info.id}]-headers {[% for hdr in info.headers %][{hdr.k}] "[{hdr.v}]"
                    [% endfor %]})
(def burp[{info.id}]
  (client/request
   (merge
    common-opts
    {:method [{info.method}]
     :url burp[{info.id}]-url
     :headers burp[{info.id}]-headers[% if info.body|not-empty %][% if info.content-type = "application/json" %]
     :content-type :json
     :form-params [{info.body}][% elif info.content-type = "application/x-www-form-urlencoded" %]
     :form-params [{info.body}][% else %]
     :body (-> "[{info.body}]"
               (.getBytes "ISO-8859-1"))
     [% endif %][% endif %]
     :cookie-store my-cs})))
[% endfor %]
[% endsafe %]
