(ns cyber-chef
  (:require [seesaw.core :as gui]
            [clojure.java.browse :refer [browse-url]]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.i18n :as i18n]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper]))

;;;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "CyberChefhelper"
        :menu-cyber-chef "CyberChef Magic"
        }

   :zh {:script-name "CyberChef辅助"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;;;;;;;
(defn browse-cyber-chef
  [input]
  (->> (helper/base64-encode input)
       (str "https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=" )
       browse-url))

(def menu-context #{:message-editor-request
                    :message-editor-response
                    :message-viewer-request
                    :message-viewer-response})


(defn cyber-chef-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     (let [txt (context-menu/get-selected-text invocation)]
       (when-not (empty? txt)
         [(gui/menu-item :text (tr :menu-cyber-chef)
                         :enabled? true
                         :listen [:action (fn [e]
                                            (browse-cyber-chef txt))])])))))

(def reg (scripts/reg-script! :cyber-chef
                              {:name (tr :script-name)
                               :version "0.1.0"
                               :min-burp-clj-version "0.4.11"
                               :context-menu {:cyber-chef (cyber-chef-menu)}}))
