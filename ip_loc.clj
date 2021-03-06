(ns ip-loc
  (:require [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.utils :as utils]
            [burp-clj.scripts :as scripts]
            [burp-clj.proxy :as proxy]
            [burp-clj.helper :as helper]
            [burp-clj.i18n :as i18n]
            [clojure.java.io :as io])
  (:import java.net.InetAddress
           com.github.jarod.qqwry.QQWry))

;;;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "show ip location"
        }

   :zh {:script-name "显示ip地理位置"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;;;;;;
(helper/add-dep-with-proxy '[[org.clojure/core.memoize "1.0.236"]])
(require '[clojure.core.memoize :as memo])

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
  (try
    (let [loc (->> (InetAddress/getByName host)
                   (.getHostAddress)
                   (.findIP qqwry))]
      (str (.getMainInfo loc)
           " -- "
           (.getSubInfo loc)))
    (catch Exception e
      (log/error "get-ip-loc for " host " error:" e))))

(def mem-get-ip-loc
  (memo/lru get-ip-loc
            {}
            :lru/threshold 20))

(defn ip-loc
  [is-req msg]
  (when is-req
    (let [req-resp (.getMessageInfo msg)
          ip (-> (.getHttpService req-resp)
                 (.getHost))]
      (when-some [ip-loc-str (mem-get-ip-loc ip)]
        (->> (str ip-loc-str " " (.getComment req-resp))
             (.setComment req-resp))))))

(defn ip-loc-proxy []
  (proxy/make-proxy-proc ip-loc))

(def reg (scripts/reg-script! :ip-location
                              {:name (tr :script-name)
                               :version "0.2.1"
                               :min-burp-clj-version "0.5.0"
                               :proxy-listener {:ip-loc/comment-loc (ip-loc-proxy)}
                               }))
