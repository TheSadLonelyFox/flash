package com.pubnub.operation {
	import com.adobe.crypto.*;
	import com.pubnub.*;
	import com.adobe.serialization.json.JSON;
	import com.pubnub.loader.*;
	/**
	 * ...
	 * @author firsoff maxim, firsoffmaxim@gmail.com, icq : 235859730
	 * //fixed by TheSadLonelyFox
	 */
	public class PublishOperation extends Operation {
		
		public var origin:String = "0"; 
		public var secretKey:String; 
		public var cipherKey:String = ""; 
		public var publishKey:String = ""; 
		public var subscribeKey:String = ""; 
		
		override public function send(args:Object):void {
			channel = args.channel;
			var message:Object = args.message;//Sending String Instead of Object:fixed
			if (channel == null || message == null) {
				dispatchEvent(new OperationEvent(OperationEvent.FAULT, [ -1, "Channel Not Given and/or Message"]));
				return;
			}
			var signature:String = "0";
			var serializedMessage:String = JSON.encode(message);
			if (secretKey){
				// Create the signature for this message                
				var concat:String = publishKey + "/" + subscribeKey + "/" + secretKey + "/" + channel + "/" + serializedMessage;
				
				// Sign message using HmacSHA256
				signature = HMAC.hash(secretKey, concat, SHA256);        
			}
			
			if(cipherKey && cipherKey.length > 0){
				serializedMessage = JSON.encode(PnCrypto.encrypt(cipherKey, serializedMessage));
			}
			
			uid = PnUtils.getUID();
			_url = origin + "/" + "publish" + "/" + publishKey + "/" + subscribeKey + "/" + signature + "/" + PnUtils.encode(channel) + "/" + 0 + "/" +PnUtils.encode(serializedMessage as String);
			_loader.load(this._url);
		}
		
		override protected function onLoaderData(e:PnURLLoaderEvent):void {
			try {
				dispatchEvent(new OperationEvent(OperationEvent.RESULT, JSON.decode(String(e.data))));
			}
			catch (e:*){
				dispatchEvent(new OperationEvent(OperationEvent.FAULT, [-1, "[Pn.publish()] JSON.parse error"] ));
			}
		}
	}
}