(ns ip-loc
  (:require [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.proxy :as proxy]))


(utils/add-dep '[[ntestoc3/netlib "0.3.4-SNAPSHOT"]])
(require '[netlib.qqwry :as qqwry])


(defn ip-loc
  [is-req msg]
  (when is-req
    (let [req-resp (.getMessageInfo msg)
          ip (-> (.getHttpService req-resp)
                 (.getHost))
          ip-geo (qqwry/get-location ip)
          ip-loc-str (str (:county ip-geo) " -- " (:area ip-geo))]
      (.setComment req-resp ip-loc-str))))

(defn ip-loc-proxy []
  (proxy/make-proxy-proc ip-loc))

(def reg (scripts/reg-script! :ip-location
                              {:name "show ip location"
                               :version "0.0.1"
                               :min-burp-clj-version "0.1.0"
                               :proxy-listener {:ip-loc/comment-loc (ip-loc-proxy)}
                               }))
