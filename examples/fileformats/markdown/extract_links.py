#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : extract_links.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Nov 2022

from sectools.fileformats import Markdown

md = Markdown("""[start](https://start.com/)
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla facilisis molestie enim, id consectetur neque hendrerit vel. Interdum et malesuada fames ac ante ipsum primis in faucibus. Fusce consectetur nisi at nisl porttitor scelerisque. Proin lacinia purus sit amet nulla semper consectetur. Maecenas vestibulum gravida viverra. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Aenean facilisis tellus in orci lobortis auctor. Nulla non nulla non mauris elementum vehicula nec quis risus. Maecenas porta, leo at malesuada dictum, felis nisi facilisis sem, vitae commodo neque metus venenatis augue. Suspendisse gravida sem quis urna accumsan, quis ullamcorper nulla rutrum. Nam eu dapibus massa. Nullam porttitor, erat in lobortis dignissim, sapien orci facilisis eros, quis porttitor elit ex semper neque. Mauris semper nunc posuere, iaculis sapien id, vestibulum augue.

[donec](https://donec.com/) bibendum nulla id ipsum ultricies lobortis. Donec cursus arcu sem, in fermentum tortor faucibus vitae. Nam pretium mollis nisl sed bibendum. Vestibulum ipsum ex, sollicitudin accumsan ipsum a, rhoncus porttitor diam. Quisque in elit sed sapien porttitor blandit vel ut massa. Nulla efficitur, nunc ut feugiat luctus, enim lacus gravida dolor, id vehicula tellus nulla dictum lacus. Ut suscipit turpis mi. Etiam at faucibus diam, vitae blandit erat.

Ut commodo luctus maximus. Vivamus interdum ligula feugiat, [dignissim](https://dignissim.com/) dolor quis, sagittis tellus. Fusce vitae lobortis urna. Duis vel commodo metus, auctor semper est. Vivamus laoreet pellentesque dui eget dictum. Donec consequat, nisi eu bibendum bibendum, mi nisl tempor turpis, sit amet venenatis ligula enim non sem. Aenean tincidunt nibh quis felis egestas, a pulvinar risus volutpat. Aenean gravida, est sed aliquet bibendum, mi sem dignissim turpis, id vehicula enim velit luctus nibh. Proin sit amet dolor egestas ipsum blandit maximus. Nulla facilisi.

Sed aliquet molestie libero eu fermentum. In suscipit non sapien et efficitur. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec non lacinia ligula, sed lobortis lorem. Vestibulum ac tristique magna. Duis sed justo sed massa iaculis lacinia. Integer et metus id arcu bibendum semper vitae in nisi. Donec pulvinar sed justo at ullamcorper. Cras accumsan turpis nec nisl pretium, id elementum justo elementum. Quisque ullamcorper feugiat tellus, consequat sollicitudin quam pretium in. Phasellus pharetra aliquam magna vel fringilla. Duis non pharetra dolor. Quisque posuere odio vitae est suscipit, vitae dapibus nibh auctor. Duis commodo mauris quis eleifend lobortis. Praesent vel odio felis. Pellentesque scelerisque ornare egestas.

Nunc id felis aliquam erat tempor lobortis. Vestibulum neque mi, feugiat et neque eu, tempor pretium quam. Aliquam ut hendrerit eros, eu fermentum massa. Phasellus pharetra erat vitae pellentesque luctus. Phasellus a cursus erat, sit amet lacinia risus. Donec porta ut nisi sed tempor. Etiam eu efficitur odio. Integer auctor lectus lectus. Curabitur sit amet lacus et leo semper finibus. Nullam eget quam euismod, sagittis ipsum eget, eleifend nunc. Phasellus vel laoreet ante, ut venenatis felis. Etiam tristique sapien dignissim mauris bibendum, vel porta enim porta. 
""")

print("[+] Links: ")
for link in md.extract_links():
    print(link)

print("[+] Images: ")
for link in md.extract_images():
    print(link)