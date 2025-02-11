package runner

import (
	"github.com/projectdiscovery/gologger"
)

var banner = (`
 ::::::::  :::::::::  :::::::::     :::     
:+:    :+: :+:    :+: :+:    :+:  :+: :+:   
+:+    +:+ +:+    +:+ +:+    +:+ +:+   +:+  
+#+    +:+ +#++:++#+  +#++:++#+ +#++:++#++: 
+#+    +#+ +#+        +#+       +#+     +#+ 
#+#    #+# #+#        #+#       #+#     #+# 
 ########  ###        ###       ###     ### 
`)

var version = "v1.0.2"

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tgithub.com/oneaudit\n\n")
}
