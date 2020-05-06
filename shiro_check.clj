(ns shiro-check
  (:require [burp-clj.proxy :as proxy]
            [burp-clj.helper :as helper]
            [burp-clj.scripts :as scripts]
            ))

(defn shiro-check
  [is-req msg]
  (let [req-resp (.getMessageInfo msg)
        req (.getRequest req-resp)
        jsession-id (helper/get-request-parameter req "JSESSIONID")]
    (when jsession-id
      (if is-req
        (when (not (helper/get-request-parameter req "rememberMe"))
          (->> (helper/build-parameter "rememberMe" "test" :cookie)
               (helper/add-parameter req)
               (.setRequest req-resp)))
        (let [resp (-> (.getResponse req-resp)
                       helper/analyze-response)
              org-comment (.getComment req-resp)]
          (when (->> (:cookies resp)
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
