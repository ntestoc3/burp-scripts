(ns test-payload
  (:require [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.intruder-payload :as payload]
            [burp-clj.helper :as helper]))

(defn make-payload
  []
  (payload/make-payload-generator-factory
   "test-generator"
   (fn [_]
     (payload/make-simple-payload-generator [1 3 5 7 9 10 false "hahah" nil 999]))))

(def reg (scripts/reg-script! :test-payload-gen
                              {:name "test-payload-generator"
                               :version "0.0.1"
                               :min-burp-clj-version "0.2.0"
                               :intruder-payload-generator {:test-payload (make-payload)}
                               }))
