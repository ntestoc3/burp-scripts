(ns ip-loc
  (:require [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.utils :as utils]
            [burp-clj.scripts :as scripts]
            [burp-clj.proxy :as proxy]
            [burp-clj.helper :as helper]
            [clojure.java.io :as io])
  (:import java.net.InetAddress))

(helper/add-dep-with-proxy '[[com.github.jarod/qqwry-java "0.8.0"]])
(import 'com.github.jarod.qqwry.QQWry)

(defn file->bytes [file]
  (with-open [xin (io/input-stream file)
              xout (java.io.ByteArrayOutputStream.)]
    (io/copy xin xout)
    (.toByteArray xout)))

(defonce qqwry (-> (io/resource "qqwry.dat")
                   file->bytes
                   (QQWry.)))

(log/info "ip-loc qqwry version:" (.getDatabaseVersion qqwry))

(defn get-ip-loc
  [host]
  (let [loc (->> (InetAddress/getByName host)
                 (.getHostAddress)
                 (.findIP qqwry))]
    (str (.getMainInfo loc)
         " -- "
         (.getSubInfo loc))))

(defn ip-loc
  [is-req msg]
  (when is-req
    (let [req-resp (.getMessageInfo msg)
          ip (-> (.getHttpService req-resp)
                 (.getHost))]
      (try (let [ip-loc-str (str (get-ip-loc ip) " "
                                 (.getComment req-resp))]
             (.setComment req-resp ip-loc-str))
           (catch Exception e
             (log/error "ip loc for:" (.getUrl req-resp) "ip:" ip))))))

(defn ip-loc-proxy []
  (proxy/make-proxy-proc ip-loc))

(def reg (scripts/reg-script! :ip-location
                              {:name "show ip location"
                               :version "0.0.1"
                               :min-burp-clj-version "0.1.0"
                               :proxy-listener {:ip-loc/comment-loc (ip-loc-proxy)}
                               }))
