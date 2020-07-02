(ns shiro-check
  (:require [burp-clj.proxy :as proxy]
            [burp-clj.helper :as helper]
            [taoensso.timbre :as log]
            [burp-clj.scripts :as scripts]
            ))

(defn shiro-check
  [is-req msg]
  (let [req-resp (.getMessageInfo msg)
        req (.getRequest req-resp)
        jsession-id (or (helper/get-request-parameter req "JSESSIONID")
                        (helper/get-request-parameter req "SESSION"))]
    (when jsession-id
      (if is-req
        (when (not (helper/get-request-parameter req "rememberMe"))
          (->> (helper/build-parameter "rememberMe" "test" :cookie)
               (helper/add-parameter req)
               (.setRequest req-resp)))
        (let [resp-cookies (->> (.getResponse req-resp)
                                helper/analyze-response
                                .getCookies
                                (map helper/parse-cookie))
              org-comment (.getComment req-resp)]
          (when (->> resp-cookies
                     (take-while #(and (= (:name %) "rememberMe")
                                       (= (:value %) "deleteMe")))
                     seq)
            (doto req-resp
              (.setHighlight "orange")
              (.setComment (str "maybe Shiro! " org-comment)))))))))

(defn shiro-check-proxy []
  (proxy/make-proxy-proc shiro-check))

(def reg (scripts/reg-script! :shiro-check
                              {:name "jsp shiro check"
                               :version "0.0.1"
                               :min-burp-clj-version "0.1.1"
                               :proxy-listener {:shiro-check/cookie-check (shiro-check-proxy)}
                               }))
