package com.pubnub {
	import com.pubnub.operation.*;
	import flash.events.*;
	
	/**
	 * ...
	 * @author firsoff maxim, firsoffmaxim@gmail.com, icq : 235859730
	 */
	public class PnEvent extends Event {
		
		public static const INIT:String = "init";
		public static const INIT_ERROR:String = "initError";
		public static const SUBSCRIBE:String = 'subscribe';
		public static const DETAILED_HISTORY:String = 'detailed_history';
		public static const PUBLISH:String = 'publish';
		
		public var operation:Operation;
		
		private var _status:String;
		private var _channel:String;
		private var _data:Object;
		
		public function PnEvent(type:String, data:Object = null, channel:String = null, status:String = null,  bubbles:Boolean = false, cancelable:Boolean = false) { 
			_channel = channel;
			_status = status;
			_data = data;
			super(type, bubbles, cancelable);
		} 
		
		public override function clone():Event { 
			return new PnEvent(type, data , channel, status,bubbles, cancelable);
		} 
		
		public override function toString():String { 
			return formatToString("PnEvent", "type", "data" , "channel", "status", "bubbles", "cancelable", "eventPhase"); 
		}
		
		public function get status():String {
			return _status;
		}
		
		public function get channel():String {
			return _channel;
		}
		
		public function get data():Object {
			return _data;
		}
		
	}
}