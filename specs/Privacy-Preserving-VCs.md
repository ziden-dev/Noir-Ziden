# W3C Verifiable Credentials (VCs)

In definition, credential is any type of document that states some facts about an entity in real life. For example, it can be a driver license, identity card, credit card,... In the digital world, it characterizes the identity of its owner.
The W3C organization has standardized the process of issuing, managing and presenting digital credential data on the internet. They clarify the roles of 3 main actors: Issuer, Verifier, and Holder.

<img style="width:100%;height:643px;" src="images/3 actors.png">

  - Issuer: any individual or organization who has authority and reputation to validate and grant certificates in form of Verifiable Credentials (VCs) for the holder
  - Holder: end user who wants to prove who they are in the digital world. As submitting their personal data for the Issuer, they are granted VCs and then present them to the Verifier to gain access to their services.
  - Verifier: any service or protocol in the digital world ( both Web2 and Web3 ) who requires credential data from users to let them use their products. They trust certain Issuers and only accept the VCs which are granted by them.
Thanks to its effectiveness, scalability and compatibility, this standard is trusted and implemented by many protocols such as: [EBSI](https://ec.europa.eu/digital-building-blocks/wikis/display/EBSI/Home), [vLEI](https://www.gleif.org/en/vlei/introducing-the-verifiable-lei-vlei), [Cogmento](https://cogmento.com/),... each one has their own method of structuring and presenting VCs, tailored to their use cases.

# Privacy Issues with traditional W3C implementations

Aforementioned protocols all fail to protect the privacy for the holders, since in the VCs presentation phase, holders have no other choices but to send directly their VCs to the verifiers. Even though some of these protocols have already applied selective disclosure which means the holder only has to share some pieces of their VCs that are necessary in the context of the verifier, overtime when the holder participates in different services, especially ones that run on the transparent Web3 environments, their data will still be exposed and resembled. 

# Solution

Applying Zero-knowledge proof in presenting VCs has been proven to be one of the best strategies to preserve the user's privacy.

<img style="width:100%;height:643px;" src="images/PP-VC.png">

As demonstrated in the example diagram, instead of sending directly raw data for the verifier, the holder now can just generate a ZK-proof on their data, convincing the verifier that they are qualified for some specific requirements without revealing any other irrelevant information. In the case illustrated in the diagram, the Holder proves that he is older than 18, and has the Nationality being one of USA, Canada, Mexico, the Verifier couldn't extract his real name and real nationality.
This strategy has been used by numerous identity protocols to enhance their user's security with some prominent names being [Polygon ID](https://polygon.technology/polygon-id), [Dock.io](https://www.dock.io/), [zCloak](https://zcloak.network/), etc.