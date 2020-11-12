(ns multi
  (:require [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.utils :as utils]
            [burp-clj.extender :as extender]
            [burp-clj.helper :as helper]
            [burp-clj.scripts :as scripts]))


(comment
  (helper/add-dep-with-proxy '[[com.climate/claypoole "1.1.4"]])
  (require '[com.climate.claypoole :as cp])


  (def r (cp/upmap 500
                   (fn [_]
                     (extender/make-http-req  "cn.bing.com" 443 true
                                              (.getBytes "GET / HTTP/1.1
Host: cn.bing.com
Connection: close
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36
Accept: */*
Sec-Fetch-Site: none
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate
Accept-Language: zh-HK,zh;q=0.9,ja;q=0.8,en;q=0.7,zh-CN;q=0.6

")))
                   (range 200)))


  )


