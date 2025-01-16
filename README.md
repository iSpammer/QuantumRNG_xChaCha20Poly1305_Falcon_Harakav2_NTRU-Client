# QuantumRNG_xChaCha20Poly1305_Falcon_Harakav2_NTRU-Client
### Run same cmd as the server and no frag too!
server and client are last updated able masafer hollanda :) 15/5


### Run the following cmds to be able to run
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
always run no frag server

# Updated to include UDP Open Secure Stateless Authentication and Mutual Assessment (uOSSAMA) Layer
## this new UDP protocol is WIP!

## Citation

Please cite the following work if it will be used, 2 more papers are comming:

```bibtex
@InProceedings{10.1007/978-3-031-47594-8_1,
author="Hussien, Osama A. A. M.
and Arachchige, Isuru S. W.
and Jahankhani, Hamid",
editor="Jahankhani, Hamid",
title="Strengthening Security Mechanisms of Satellites and UAVs Against Possible Attacks from Quantum Computers",
booktitle="Cybersecurity Challenges in the Age of AI, Space Communications and Cyborgs",
year="2024",
publisher="Springer Nature Switzerland",
address="Cham",
pages="1--20",
abstract="The mounting prevalence of quantum computing poses a threat not only to conventional but also to futuristic network systems. As a result, today the focus shifts towards strengthening existing networks to secure sensitive data that may be threatened as a result of the potential for breaking present encryption protocols with the introduction of quantum computing. Cryptography, commonly referred to as encryption, is the underlying principle that enables safe data storage and communication. Cryptography involves key distribution, for which the current best method is a public key distribution based on principles such as Diffie-Hellman key exchange. However, these principles rely on classical computer limitations, such as factoring big numbers, which are expected to be eliminated with quantum computers and algorithms. This research provides an overview of using Quantum Key Distribution (QKD) protocols for satellite-based and Unmanned-Aerial-Vehicle (UAV) related communication. This research also proposes a none QKD protocol to provide an understanding of analysis of the advantages and applications of these protocols. As several QKD protocols have been proposed in the past, identifying the advantages and unique performance characteristics of these protocols is important, especially when adapting these protocols to specific use cases such as satellite-based communications and UAV-related communications.",
isbn="978-3-031-47594-8"
}
```

and
```bibtex
@Inbook{Hasanaj2024,
author="Hasanaj, Krison
and Hussien, Osama Akram Amin Metwally
and Jahankhani, Hamid",
editor="Jahankhani, Hamid
and Kendzierskyj, Stefan
and Pournouri, Sina
and Pozza, Maria A.",
title="Secure and Resilient IP-Satellite Communication Infrastructure",
bookTitle="Space Governance: Challenges, Threats and Countermeasures",
year="2024",
publisher="Springer Nature Switzerland",
address="Cham",
pages="129--161",
abstract="Ground-based satellite operations play a pivotal role in ensuring the seamless functioning of satellites orbiting our planet. These operations, however, are not immune to the ever-evolving landscape of cybersecurity risks and threats with the rise of quantum computing. The integrity, confidentiality, and availability of critical satellite data and services are at stake. In response to this challenge, this chapter endeavors to construct a robust cryptographic framework for mitigating the cybersecurity risks associated with the current standard cryptographic algorithms employed in IP communication for ground-based satellite operations. These algorithms, while widely used, face vulnerabilities that can be exploited by malicious actors when quantum computing become mainstream, our investigation aims to identify a promising candidate protocol that can effectively address these risks. This protocol should exhibit resilience against cyber threats from quantum computing, ensuring the secure transmission of data between ground stations and satellites. By doing so, we pave the way for a more secure and resilient IP-satellite communication infrastructure, safeguarding critical operations in an era where cybersecurity is paramount.",
isbn="978-3-031-62228-1",
doi="10.1007/978-3-031-62228-1_5",
url="https://doi.org/10.1007/978-3-031-62228-1_5"
}
```
